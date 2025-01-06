import os
from dotenv import load_dotenv

import boto3
import certifi
from boto3.exceptions import S3UploadFailedError
from botocore.exceptions import ClientError


load_dotenv()

endpoint_url = os.getenv('S3_ENDPOINT')
aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
bucket = 'flask-app'

s3 = boto3.client('s3',
                  endpoint_url=endpoint_url,
                  aws_access_key_id=aws_access_key_id,
                  aws_secret_access_key=aws_secret_access_key,
                  verify=False
                  )

response = s3.list_buckets()


def upload(file, filename):
    try:
        s3.upload_fileobj(file, bucket, filename)
        print(" Upload Successful")
    except S3UploadFailedError as e:
        print(f"Failed to upload file to S3.{e}")


def download(filename):
    try:
        pre_signed_url = s3.generate_presigned_url('get_object',
                                                   Params={'Bucket': bucket,
                                                           'Key': filename,
                                                           'ResponseContentDisposition': 'inline',
                                                           'ResponseContentType': 'image/jpg'},
                                                   ExpiresIn=1200)
    except ClientError as e:
        print(f"client error{e}")
        return None

    return pre_signed_url
