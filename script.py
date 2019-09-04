import os
import json
import logging

import boto3
import requests
import opencrypt

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
logger.addHandler(handler)


def _exit(code, message):

    return {'statusCode': code, 'body': json.dumps({
        'error' if code >= 300 else 'success': message})}


def read_config():

    if not os.environ.get('CONFIG_FILE'):
        return _exit(404, 'No CONFIG_FILE environment variable exists.')

    config_file = os.environ['CONFIG_FILE']
    if config_file.startswith(('http', 'https', 'ftp')):
        logger.info('Config file prefix tells program to fetch it online.')
        logger.info('Fetching config file: %s' % (config_file))
        response = requests.get(config_file)

        if response.status_code < 400:
            ciphertext = response.content
        else:
            return _exit(400, 'Could not fetch config file: '
                         '%s' % (response))
    else:
        logger.info('Config file prefix tells program to search ' +
                    'for it on filesystem.')
        if not os.path.isfile(config_file):
            return _exit(404, 'No Config file on filesystem: '
                         '%s' % (config_file))

        ciphertext = open(config_file, 'rb').read()

    content = opencrypt.decrypt_file(
        ciphertext, write_to_file=False, is_ciphertext=True)
    try:
        config = json.loads(content)
        validation = validate_config(config)

        if validation and validation.get('statusCode'):
            return validation
        return config
    except json.JSONDecodeError as exc:
        return _exit(400, str(exc))


def validate_config(config):

    if not (config.get('lb_arns') or config.get('ebstalk_envs')):
        return _exit(404, 'Either `lb_arns` or `ebstalk_envs` fields '
                     'must be defined in config.')
    if not config.get('slack_hooks'):
        return _exit(404, 'No `slack_hooks` field defined in config.')


def alert_on_slack(config, arns):

    if not arns:
        logger.info('No text to push to slack.')
        return

    for url in config['slack_hooks']:
        response, _count = (None, 0)
        while not response and _count < 5:
            text = 'Following LBs have no WAF associated.\n'
            for arn in arns:
                text += '*`%s`*\n' % (arn)
            try:
                response = requests.post(url, json={'text': text})
            except:
                logger.info('Could not send slack request. ' +
                            'Retrying after 10 secs...')
                time.sleep(10)
                _count += 1

        if not response:
            continue

        if response.status_code == 200:
            logger.info('Pushed message to slack successfully.')
        else:
            logger.info('Could not push message to slack: <(%s) %s>' % (
                response.status_code, response.content.decode('utf8')))


def main(event, context):

    config = read_config()
    if config.get('statusCode'):
        logger.info(config)
        return config

    orig_elbs = set(config.get('lb_arns'))
    logger.info('[%d] LBs to watch for WAF association.', len(orig_elbs))
    orig_envs = set(config.get('ebstalk_envs'))
    logger.info('[%d] ElasticBeanStalk environments to watch.', len(orig_envs))
    if not (orig_elbs or orig_envs):
        return _exit(200, 'Everything executed smoothly.')

    logger.info(str())
    session = boto3.session.Session(profile_name='ebryx-soc-l5')
    ebstalk = session.client('elasticbeanstalk')
    logger.info('Created ElasticBeanStalk client.')

    envs = ebstalk.describe_environments(
        MaxRecords=999).get('Environments', list())
    logger.info('[%d] ElasticBeanStalk environments fetched.', len(envs))

    for env in envs:
        if env.get('EnvironmentId') not in orig_envs and \
                env.get('EnvironmentArn') not in orig_envs and \
                env.get('EnvironmentName') not in orig_envs:
            continue

        logger.info('  Fetching environment resources...')
        elbs = [
            x.get('Name') for x in ebstalk
            .describe_environment_resources(
                EnvironmentId=env['EnvironmentId']).get(
                    'EnvironmentResources', dict()).get(
                        'LoadBalancers', list()) if x.get('Name')]

        orig_elbs = orig_elbs | set(elbs) if elbs else orig_elbs

    logger.info('[%d] LBs to watch for WAF association.', len(orig_elbs))
    logger.info(str())

    waf = session.client('waf-regional')
    logger.info('Created WAF Regional client.')

    acls = waf.list_web_acls(Limit=100).get('WebACLs', list())
    logger.info('[%d] Web ACLs fetched.', len(acls))

    for acl in acls:
        arns = waf.list_resources_for_web_acl(
            WebACLId=acl['WebACLId']).get('ResourceArns', list())
        orig_elbs = orig_elbs - set(arns)
        if not orig_elbs:
            logger.info('No LBs remaining to watch.')
            break

    logger.info(str())
    logger.info('Fetching all ELBs from AWS.')
    elbclient = session.client('elbv2')
    all_elbs = [
        x.get('LoadBalancerArn') for x in elbclient
        .describe_load_balancers().get('LoadBalancers', list())
        if x.get('LoadBalancerArn')]
    logger.info('[%d] Total ELBs fetched from AWS.', len(all_elbs))

    orig_elbs = [x for x in orig_elbs if x in all_elbs]
    alert_on_slack(config, orig_elbs) if orig_elbs else None


if __name__ == "__main__":
    main({}, {})
