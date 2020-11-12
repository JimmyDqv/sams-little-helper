# SAMs Little Helper

This is a collection of scripts to help and make developing AWS Lambda function using [SAM][aws-sam-link] a bit easier.  

## SAM IAM Helper

A script to help you during local development and function invocation. Normally the function is invoked locally using the AWS cli credentials you have configured.  
This works fine but sometimes you like to invoke the function with the exact permissions for the Lambda function, to catch any IAM related problems.

## Installation

Copy the script sam-iam-helper.py to a location of your choice on your development machine. Make the file executable or run it with python3


## Usage

Run the script with one of the defined commands, list, create, or assume.
The script will run using you configured IAM credentials, so make sure you have access enough permissions, CloudFormation, IAM, STS.

```shell
./sam-iam-helper.py <command> [parameters]
or
python3 
```

When a IAM Role has been assumed you can use the profile when invoking SAM Local to ensure you run with the same permissions as the Lambda Function.
Either set the profile for the entire terminal:

**Linux / Mac**
```shell
export AWS_PROFILE=sams_helper
```

**Windows**
```shell
setx AWS_PROFILE sams_helper
```

or specify the --profile parameter for [sam local invoke][aws-sam-local-invoke-link]
```shell
sam local invoke [OPTIONS] [FUNCTION_IDENTIFIER]
```

### List Command

The _list_ command print the Lambda functions name and associated roles created in a Cloudformation Stack.

> The _list_ command take two parameters.
>     
> --stackname, required, specifies the name of the deployed CloudFormation stack to get information from.  
>   
> --region, optional, specifies the AWS region to use.

```shell
./sam-iam-helper.py list --stackname my-cool-stack --region eu-north-1
```

### Create Command

The _create_ command will create a IAM Role with the same permissions as the Role used by the Lambda function. The IAM Role and Policies will be prefixed with *sams_helper* and will have Tag *CreatedBy* set to *sam_iam_helper*. The trust policy will be modified and will add a trust to current account.

> The _create_ command take three parameters.
>     
> --stackname, required, specifies the name of the deployed CloudFormation stack to get information from.  
>     
> --functionname, required, specifies the Lambda function to create a cloned IAM Role for.
>     
> --region, optional, specifies the AWS region to use.

```shell
./sam-iam-helper.py list --stackname my-cool-stack --functionname my-awesome-function --region eu-north-1
```

### Assume Command

The _assume_ command will assume the IAM Role, get temporary credentials and store them under a profile in the AWS cli credentials file. The default profile name used is *sams_helper*, this value can be overridden. If the IAM Role doesn't exist it will first be created.

> The _assume_ command take five parameters.
>     
> --stackname, required, specifies the name of the deployed CloudFormation stack to get information from.  
>     
> --functionname, required, specifies the Lambda function to create a cloned IAM Role for.
>     
> --region, optional, specifies the AWS region to use.
>     
> --duration The session duration for the assumed role, default is 3600 seconds. 
>     
> --profile The named credentials profile to store the session credentials under, default sams_helper


[aws-sam-local-invoke-link]: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-local-invoke.html
[aws-sam-link]: https://docs.aws.amazon.com/serverless-application-model/index.html