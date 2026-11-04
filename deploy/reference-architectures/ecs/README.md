# Lightwork on AWS ECS (Fargate)

Single-service deployment: one Fargate task running the dashboard, state on
EFS (so redeploys keep `~/.maverick`), secrets from SSM Parameter Store.

## Steps

1. **Build + push the image**

   ```bash
   docker build -f deploy/docker/Dockerfile -t maverick:latest .
   aws ecr create-repository --repository-name maverick
   docker tag maverick:latest ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/maverick:latest
   docker push ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/maverick:latest
   ```

2. **Store both required credentials**

   ```bash
   aws ssm put-parameter --name /maverick/anthropic-api-key \
     --type SecureString --value "sk-ant-..."
   aws ssm put-parameter --name /maverick/dashboard-token \
     --type SecureString \
     --value "$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
   aws ssm get-parameters --names /maverick/anthropic-api-key /maverick/dashboard-token \
     --query 'Parameters[].Name' --output text
   ```

3. **Create an EFS file system** (and an access point if you prefer), note the
   `fs-XXXXXXXX` id, and allow the task security group on port 2049.

4. **Register the task definition** (edit `task-definition.json` placeholders:
   `ACCOUNT_ID`, `REGION`, `fs-XXXXXXXX`):

   ```bash
   aws ecs register-task-definition \
     --cli-input-json file://deploy/reference-architectures/ecs/task-definition.json
   ```

5. **Create the service** behind an internal ALB targeting port 8765:

   ```bash
   aws ecs create-service --cluster maverick --service-name maverick \
     --task-definition maverick --desired-count 1 --launch-type FARGATE \
     --network-configuration 'awsvpcConfiguration={subnets=[subnet-...],securityGroups=[sg-...],assignPublicIp=DISABLED}'
   ```

## Notes

- **desired-count stays 1**, including with a Postgres world model. Workflow,
  A2A, audit, learning, and policy stores are not all shared yet. Use Postgres
  (RDS) for database HA/isolation and scale separate remote workers.
- One-shot goals: `aws ecs run-task` with command
  `["start", "your goal text"]` reuses the same task definition.
- The execution role needs `ssm:GetParameters` on both credential parameters and ECR pull;
  the task role needs nothing AWS-side unless your goals use AWS tools.
