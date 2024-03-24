# Localstack

Use localstack to provision resources locally for testing.
[resources](https://docs.localstack.cloud/references/init-hooks/)

To execute aws cli commands when LocalStack becomes ready, simply create a script `init-aws.sh`
and mount it into`/etc/localstack/init/ready.d/`
