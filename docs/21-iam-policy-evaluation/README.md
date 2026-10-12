# Lab 21: IAM Policy Evaluation & Least Privilege

## Overview

This lab focused on understanding how AWS IAM evaluates permissions across multiple policy types and how least-privilege access can be validated using real AWS tooling.

The goal was not only to understand IAM terminology, but to reason through why a request is allowed or denied and verify those decisions using the AWS IAM Policy Simulator and IAM Access Analyzer.

Topics included:

- Identity-based policies
- Resource-based policies
- Trust policies
- Permissions boundaries
- Service Control Policies
- Session policies
- Conditions
- Explicit and implicit deny
- `iam:PassRole`
- `NotAction`
- `NotResource`
- ABAC and resource tags
- Cross-account access
- External IDs
- Source identity
- Role chaining
- Session tags
- Managed vs inline policies
- Policy versioning
- IAM Policy Simulator
- IAM Access Analyzer
- Least-privilege refinement

---

## IAM Policy Evaluation Mental Model

A useful starting point for evaluating an AWS request is:

    Who is making the request?
            ↓
    What action are they requesting?
            ↓
    What resource are they targeting?
            ↓
    Which policies apply?
            ↓
    Do any conditions apply?
            ↓
    Is there an explicit Deny?
            ↓
    Is there an applicable Allow?
            ↓
    ALLOW or DENY

One of the most important IAM rules is:

    Explicit Deny > Explicit Allow

If no applicable Allow exists:

    No Allow
    → Implicit Deny

If an Allow exists but another applicable policy explicitly denies the action:

    Allow
    +
    Explicit Deny
    → DENY

---

## Trust Policies vs Permission Policies

A trust policy determines:

    Who can assume a role?

A permission policy determines:

    What can the role do after it is assumed?

Example:

    GitHub OIDC
        ↓
    Trust policy allows role assumption
        ↓
    GitHub assumes Terraform role
        ↓
    Permission policies determine AWS API access

A correct trust policy does not automatically grant AWS service permissions.

---

## Implicit vs Explicit Deny

Example:

    Identity policy:
    Allow ec2:*

    Another policy:
    Deny ec2:TerminateInstances

Result:

    ec2:DescribeInstances
    → Allowed

    ec2:RunInstances
    → Allowed

    ec2:TerminateInstances
    → Explicitly Denied

Even though `ec2:*` includes `TerminateInstances`, the explicit Deny takes precedence.

---

## iam:PassRole

`iam:PassRole` allows a principal to delegate an IAM role to an AWS service.

Mental model:

    AssumeRole
    = "I become this role."

    PassRole
    = "I allow an AWS service to use this role."

Example from this homelab:

    GitHub deployment role
            ↓
    Terraform creates EC2
            ↓
    EC2 receives
    homelab-cloudwatch-agent-role

The GitHub deployment role does not become the CloudWatch role.

It passes the role to EC2.

Without the required `iam:PassRole` permission, EC2 creation with the requested instance profile fails.

A future hardening improvement would be to restrict PassRole using:

    iam:PassedToService

For example:

    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::<ACCOUNT_ID>:role/homelab-*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": [
            "ec2.amazonaws.com",
            "vpc-flow-logs.amazonaws.com"
          ]
        }
      }
    }

---

## IAM Conditions

Conditions restrict when an Allow or Deny applies.

Mental model:

    Action
    = what can be done

    Resource
    = what it can be done to

    Condition
    = under what circumstances

Example:

    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "203.0.113.10/32"
        }
      }
    }

If the request comes from another IP:

    Condition fails
    → Allow does not apply
    → No other Allow
    → Implicit Deny

---

## Resource-Based Policies

Identity-based policies answer:

    What can this identity do?

Resource-based policies answer:

    Who can access this resource?

Common AWS services using resource policies include:

- S3
- KMS
- SQS
- SNS
- Secrets Manager

An explicit Deny in either an applicable identity or resource policy still wins.

Example:

    Identity policy:
    Allow s3:GetObject

    Bucket policy:
    Deny requests when aws:SecureTransport = false

    Request uses HTTP
    → Explicit Deny
    → Request fails

---

## Permissions Boundaries

A permissions boundary defines the maximum permissions an IAM identity may receive.

It does not grant permissions.

Example:

    Identity policy:
    Allow ec2:*

    Permissions boundary:
    Allow ec2:Describe*
    Allow ec2:StartInstances
    Allow ec2:StopInstances

Effective permissions:

    ec2:Describe*
    ec2:StartInstances
    ec2:StopInstances

`ec2:TerminateInstances` would not be permitted.

The effective permissions are effectively the intersection of the identity policy and permissions boundary.

---

## Service Control Policies

Service Control Policies operate at the AWS Organizations level.

They define the maximum permissions available to accounts or Organizational Units.

Mental model:

    Identity policy
    = what the role is allowed to do

    Permissions boundary
    = maximum permissions for the identity

    SCP
    = maximum permissions available to the account/OU

Example:

    Identity policy:
    Allow s3:*

    Permissions boundary:
    Allow s3:*

    SCP:
    Deny s3:DeleteBucket

Result:

    s3:DeleteBucket
    → Explicit Deny
    → Request fails

---

## Session Policies

Session policies can further restrict permissions for temporary STS credentials.

Example:

    Role:
    Allow ec2:*

    Session policy:
    Allow ec2:Describe*

Effective session permissions:

    ec2:Describe*

A session policy cannot grant permissions beyond what the underlying role already has.

---

## NotAction

`NotAction` reverses the action selection.

Example:

    {
      "Effect": "Deny",
      "NotAction": [
        "ec2:Describe*"
      ],
      "Resource": "*"
    }

This means:

    Deny everything
    EXCEPT
    ec2:Describe*

Important:

    Not denied
    ≠
    Automatically allowed

An applicable Allow must still exist.

---

## NotResource

`NotResource` reverses the resource selection.

Example:

    {
      "Effect": "Deny",
      "Action": "s3:DeleteObject",
      "NotResource": "arn:aws:s3:::archive-bucket/*"
    }

This means:

    Deny s3:DeleteObject
    on every resource
    EXCEPT archive-bucket/*

Again:

    Excluded from Deny
    ≠
    Automatically allowed

---

## RBAC vs ABAC

### Role-Based Access Control

RBAC grants access based on assigned roles.

Example:

    ProjectA-Developer
    ProjectB-Developer
    ProjectC-Developer

This can become difficult to scale as the number of projects and permission combinations increases.

### Attribute-Based Access Control

ABAC uses attributes such as tags.

Example:

    Principal tag:
    Project = Atlas

    Resource tag:
    Project = Atlas

Policy condition:

    Principal.Project == Resource.Project

This allows reusable policies to scale across users and resources.

Example:

    {
      "Effect": "Allow",
      "Action": "ec2:StartInstances",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:ResourceTag/Project": "${aws:PrincipalTag/Project}"
        }
      }
    }

---

## MFA Conditions

Sensitive IAM operations can be restricted using MFA-related conditions.

Example:

    Allow iam:DeleteUser
    only when
    aws:MultiFactorAuthPresent = true

If the user has not authenticated using MFA:

    Condition fails
    → Allow does not apply
    → Implicit Deny

---

## Cross-Account Access

Cross-account access requires cooperation between both sides.

Example:

    Account A
    deployment-role

    Account B
    production-deploy-role

For role assumption:

    Account A identity policy:
    Allow sts:AssumeRole

    Account B trust policy:
    Trust Account A deployment-role

Both sides must authorize the relationship.

Mental model:

    Caller permission
    +
    Target trust
    =
    AssumeRole succeeds

---

## External IDs and the Confused Deputy Problem

Third-party AWS integrations often use:

    sts:ExternalId

This helps protect against the confused deputy problem.

Example:

    Trust vendor AWS account
    AND
    require ExternalId = company-8472

If the vendor sends:

    company-1234

the trust condition fails and role assumption is denied.

External IDs help prevent one customer of a shared service from causing that service to assume another customer's role.

---

## Source Identity

`sts:SourceIdentity` preserves attribution through role sessions.

Example:

    Alice
      ↓
    DeploymentRole
      ↓
    ProductionRole
      ↓
    Terminate EC2

With:

    SourceIdentity = alice

an auditor can trace the action back to Alice instead of only seeing that `ProductionRole` performed the API request.

Mental model:

    Role session
    = which permissions were used

    Source identity
    = who initiated the chain

---

## Role Chaining

Role chaining occurs when an already-assumed role assumes another role.

Example:

    Alice
      ↓
    DeploymentRole
      ↓
    ProductionRole

Direct role sessions may use the role's configured maximum session duration.

Chained role sessions are limited to:

    1 hour

Example:

    Alice → DeploymentRole
    4-hour session

    DeploymentRole → ProductionRole
    maximum 1-hour chained session

The original DeploymentRole session remains unchanged.

---

## Session Tags and Transitive Tags

Session tags attach attributes to temporary sessions.

Example:

    Project = Atlas

A transitive session tag can propagate through role chaining.

Example:

    Alice
      ↓
    DeploymentRole
    Project=Atlas
      ↓
    ProductionRole
    Project=Atlas

If the tag is not transitive:

    ProductionRole session
    → tag missing

An ABAC policy requiring:

    aws:PrincipalTag/Project = Atlas

would then fail its condition.

The role assumption itself may still succeed.

The later resource access fails.

---

## AWS-Managed vs Customer-Managed vs Inline Policies

### AWS-Managed Policy

Created and maintained by AWS.

Example:

    ReadOnlyAccess

Advantages:

- easy to use
- broad service coverage

Disadvantages:

- may be broader than required
- AWS can update permissions

### Customer-Managed Policy

Created and maintained by the customer.

Advantages:

- reusable
- versioned
- more precise control

### Inline Policy

Embedded directly into one IAM identity.

Mental model:

    Managed policy
    = reusable permission package

    Inline policy
    = policy glued directly to one identity

Inline policies do not receive higher evaluation priority.

An explicit Deny still overrides an inline Allow.

---

## Managed Policy Versioning

Customer-managed policies support multiple versions.

Only one version is the default.

Example:

    HomelabReadPolicy

    v1:
    ec2:Describe*

    v2:
    ec2:Describe*
    s3:GetObject

If `v2` becomes the default, every identity using the policy immediately receives the updated permissions.

This can create policy drift if access reviews only inspect policy names instead of actual current policy documents.

---

## IAM Policy Simulator

The IAM Policy Simulator was used to validate real role behavior.

Mental model:

    Policy Simulator
    = "What would AWS decide if this principal attempted this action?"

### Terraform Plan Role Test

First retrieve the AWS account ID:

    aws sts get-caller-identity \
      --profile lab-admin \
      --query Account \
      --output text

Then simulate the plan role:

    aws iam simulate-principal-policy \
      --policy-source-arn arn:aws:iam::<ACCOUNT_ID>:role/github-actions-terraform-plan \
      --action-names \
        ec2:DescribeInstances \
        ec2:RunInstances \
      --profile lab-admin

Results:

    ec2:DescribeInstances
    → allowed

    ec2:RunInstances
    → implicitDeny

The Allow matched:

    ReadOnlyAccess

The RunInstances request contained:

    MatchedStatements: []

confirming there was no applicable Allow.

This validated separation between Terraform planning and deployment.

---

## Terraform Deploy Role Test

The deploy role was tested using:

    aws iam simulate-principal-policy \
      --policy-source-arn arn:aws:iam::<ACCOUNT_ID>:role/github-actions-terraform-deploy \
      --action-names \
        ec2:DescribeInstances \
        ec2:RunInstances \
        ec2:TerminateInstances \
        rds:CreateDBInstance \
      --profile lab-admin

Results:

    ec2:DescribeInstances
    → allowed

    ec2:RunInstances
    → allowed

    ec2:TerminateInstances
    → allowed

    rds:CreateDBInstance
    → implicitDeny

This demonstrated that the deployment role could manage the required EC2 infrastructure but could not create unrelated RDS resources.

---

## Explicit Deny Simulation

A temporary custom policy was created:

    cat > /tmp/explicit-deny-test.json <<'EOF'
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "ec2:*",
          "Resource": "*"
        },
        {
          "Effect": "Deny",
          "Action": "ec2:TerminateInstances",
          "Resource": "*"
        }
      ]
    }
    EOF

The simulator was run using:

    aws iam simulate-custom-policy \
      --policy-input-list "$(cat /tmp/explicit-deny-test.json)" \
      --action-names \
        ec2:DescribeInstances \
        ec2:RunInstances \
        ec2:TerminateInstances \
      --profile lab-admin

Results:

    ec2:DescribeInstances
    → allowed

    ec2:RunInstances
    → allowed

    ec2:TerminateInstances
    → explicitDeny

This directly validated:

    Explicit Deny > Explicit Allow

---

## Condition Simulation

A policy containing an IP-based condition was created:

    cat > /tmp/condition-test.json <<'EOF'
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::example-bucket/*",
          "Condition": {
            "IpAddress": {
              "aws:SourceIp": "203.0.113.10/32"
            }
          }
        }
      ]
    }
    EOF

Matching request:

    aws iam simulate-custom-policy \
      --policy-input-list "$(cat /tmp/condition-test.json)" \
      --action-names s3:GetObject \
      --resource-arns arn:aws:s3:::example-bucket/test.txt \
      --context-entries \
        ContextKeyName=aws:SourceIp,ContextKeyValues=203.0.113.10,ContextKeyType=ip \
      --profile lab-admin

Result:

    allowed

Changing the simulated source IP to:

    198.51.100.25

resulted in:

    implicitDeny

This demonstrated that a conditional Allow only applies when all required conditions are satisfied.

---

## IAM Access Analyzer

IAM Access Analyzer was used to validate IAM policy design.

Mental model:

    Policy Simulator
    → What would this request do?

    Access Analyzer
    → Does this policy design contain potentially risky patterns?

### Deliberately Broad Test Policy

A deliberately insecure policy was created:

    cat > /tmp/access-analyzer-test.json <<'EOF'
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "*",
          "Resource": "*"
        }
      ]
    }
    EOF

It was analyzed using:

    aws accessanalyzer validate-policy \
      --policy-document file:///tmp/access-analyzer-test.json \
      --policy-type IDENTITY_POLICY \
      --profile lab-admin

Access Analyzer returned findings including:

    CREATE_SLR_WITH_STAR_IN_ACTION_AND_RESOURCE

and:

    PASS_ROLE_WITH_STAR_IN_ACTION_AND_RESOURCE

The `iam:PassRole` finding was particularly important because:

    Action: "*"
    Resource: "*"

effectively includes:

    iam:PassRole
    on every role

This can create privilege-escalation risk.

---

## Real Deployment Policy Validation

The real deployment role inline policy was exported:

    aws iam get-role-policy \
      --role-name github-actions-terraform-deploy \
      --policy-name TerraformHomelabDeployment \
      --profile lab-admin \
      --query PolicyDocument \
      --output json > /tmp/terraform-deploy-policy.json

The policy can be inspected using:

    jq . /tmp/terraform-deploy-policy.json

or:

    python3 -m json.tool /tmp/terraform-deploy-policy.json

The real policy was validated:

    aws accessanalyzer validate-policy \
      --policy-document file:///tmp/terraform-deploy-policy.json \
      --policy-type IDENTITY_POLICY \
      --profile lab-admin

Result:

    {
      "findings": []
    }

This did not mean the policy was perfectly least-privilege.

It meant the policy did not trigger Access Analyzer's validation checks.

Manual review still identified broad permissions:

    ec2:*
    cloudwatch:*
    logs:*

as future candidates for refinement.

---

## Least-Privilege Review

The deploy policy currently contains broader permissions for:

    ec2:*
    cloudwatch:*
    logs:*

These are currently accepted as deliberate tradeoffs while the architecture continues to stabilize.

The refinement strategy is:

    1. Keep required broad permissions temporarily
    2. Document the exception
    3. Observe real Terraform API usage
    4. Review CloudTrail and deployment behavior
    5. Derive a narrower required action set
    6. Test the reduced policy
    7. Replace wildcards when confidence is high

This balances:

    Least privilege
    +
    Operational reliability

rather than blindly removing permissions until deployments fail.

---

## iam:PassRole Refinement

The current deployment policy scopes IAM permissions to:

    arn:aws:iam::<ACCOUNT_ID>:role/homelab-*

rather than:

    Resource: "*"

A future refinement is to further restrict role delegation using:

    iam:PassedToService

to services that actually receive IAM roles, such as:

    ec2.amazonaws.com
    vpc-flow-logs.amazonaws.com

This is different from services Terraform merely interacts with.

---

## Logging Permission Review

The deployment role currently has:

    cloudwatch:*
    logs:*

Broad logging permissions deserve additional scrutiny because they can potentially allow modification or deletion of:

- alarms
- dashboards
- log groups
- log retention
- monitoring configuration

This impacts more than deployment functionality.

It can also affect:

    Auditability
    Incident response
    Operational visibility
    Security evidence

The permissions will be refined after monitoring requirements are fully stabilized.

---

## Final Policy Evaluation Challenge

The final scenario combined multiple policy layers:

    Identity policy:
    Allow ec2:*

    Permissions boundary:
    Allow ec2:Describe*
    Allow ec2:RunInstances
    Allow ec2:TerminateInstances

    Session policy:
    Allow ec2:Describe*
    Allow ec2:RunInstances

    SCP:
    Deny ec2:TerminateInstances

    RunInstances condition:
    aws:RequestedRegion = us-east-2

Results:

    ec2:DescribeInstances
    Region: us-east-2
    → ALLOWED

All applicable permission layers allowed the request and no Deny applied.

    ec2:RunInstances
    Region: us-west-2
    → IMPLICIT DENY

The required region condition failed, so the Allow did not apply.

    ec2:TerminateInstances
    Region: us-east-2
    → EXPLICIT DENY

The SCP explicitly denied the action, overriding all applicable Allows.

---

## Problems Encountered

### simulate-custom-policy File Input

Initial command:

    aws iam simulate-custom-policy \
      --policy-input-list file:///tmp/explicit-deny-test.json

returned:

    InvalidInput
    Policy input list item 1 has invalid content

The policy document instead needed to be provided as a policy string:

    --policy-input-list "$(cat /tmp/explicit-deny-test.json)"

This successfully executed the simulation.

### jq Not Installed

Attempting:

    jq .

returned:

    zsh: command not found: jq

The package can be installed using:

    sudo apt update
    sudo apt install jq

Alternatively:

    python3 -m json.tool

can be used to format JSON without installing additional software.

---

## Key Lessons

This lab reinforced several core IAM concepts:

    Trust policy
    → who may assume a role

    Permission policy
    → what the role may do

    Explicit Deny
    → overrides applicable Allows

    Implicit Deny
    → default when no applicable Allow exists

    Permissions boundary
    → maximum identity permission ceiling

    SCP
    → organization/account-level permission ceiling

    Session policy
    → temporary-session restriction

    Resource policy
    → permissions granted by a resource

    PassRole
    → delegate a role to an AWS service

    Conditions
    → restrict when an Allow or Deny applies

    ABAC
    → authorization using attributes/tags

The biggest lesson was that IAM troubleshooting is primarily a process of determining:

    Who?
    What action?
    What resource?
    Which policy layers?
    What conditions?
    Any explicit Deny?
    Any applicable Allow?

---

## Portfolio Summary

Built and validated a least-privilege AWS IAM architecture for Terraform CI/CD using separate planning and deployment roles.

Used the AWS IAM Policy Simulator to verify authorization boundaries, including read-only plan access, deployment permissions, implicit denies, explicit denies, and conditional access.

Used IAM Access Analyzer to validate both intentionally insecure test policies and the real Terraform deployment policy.

Performed a manual least-privilege review of EC2, CloudWatch, logging, PassRole, and Terraform state permissions and documented a staged refinement strategy balancing security with operational reliability.

---

## Interview-Ready Explanation

> I designed separate IAM roles for Terraform planning and deployment so that planning workflows could inspect AWS infrastructure without having permission to modify it. I validated the roles using the IAM Policy Simulator, confirming that the plan role could describe EC2 resources but could not launch instances, while the deploy role could manage EC2 infrastructure but could not create unrelated resources such as RDS databases.
>
> I also tested explicit deny behavior and conditional policies using custom simulations, then used IAM Access Analyzer to identify risky wildcard patterns such as unrestricted `iam:PassRole`.
>
> For permissions that remain broad, such as `ec2:*` and CloudWatch logging permissions, I documented them as temporary architectural tradeoffs and established a plan to refine them using observed Terraform API behavior and audit logs once the infrastructure stabilizes.

---

## Lab Status

    Lab 21: IAM Policy Evaluation & Least Privilege
    Status: COMPLETE

Next:

    Lab 22: Advanced IAM Least-Privilege Refinement
