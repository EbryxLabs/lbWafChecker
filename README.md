# lbWafChecker
Alerts on slack if any AWS ALB is missing AWS WAF association.  
Confguration file in `.json` format is given in encrypted form and program decrypts it using AES keys provided in environment. For more information on encryption / decryption, look at [**opencrypt**](https://pypi.org/project/opencrypt/) library of python.

## AWS Lambda Deployment
- Create a deployment package, place it to S3 so you can specify it in your cloudformation process. You need make an archive containing all the required libraries as mentioned in `requirements.txt` file and python scripts containing the code.
    ```
    cd /path/to/env/lib/pythonx.x/site-packages/
    zip -r9 <archive-name> ./
    ```
    From root directory of the project, add python scripts to the same archive you created above:
    ```
    zip -g <archive-name> script.py
    ```
- Or just execute following command to create lambda deployment package named `lambda_code-YYYY-mm-ddTHH-MM-SSZ.zip` command
  ```
  /bin/bash lambda_package_creator.sh /path/to/env/lib/pythonx.x/site-packages/
  ```

## Configuration
A sample configuration file is shown below:
```
{
  "lb_arns": {
    "<arn-1-string>",
    "<arn-2-string>",
    ...
  },
  "slack_hooks": ["<hook-1-url>", ...]
}
```
**`lb_arns`** is a list of ARN strings of load balancers you want to check WAF association against.  
**`slack_hooks`** are a list of URI endpoints for alerting on slack.

## Slack Alerts
Program will notify only if ALB under watch is not associated with any WAF on AWS.