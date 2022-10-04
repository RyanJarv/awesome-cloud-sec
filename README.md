# awesome-cloud-sec
Awesome list for cloud (mostly AWS at the moment), security, pentesting related projects and libraries.

NOTE: This isn't an endorsement of any of these projects. I'm mostly using this as a way to keep track of interesting projects I come across.

# AWS

### Info
  * [aws_exposable_resources](https://github.com/SummitRoute/aws_exposable_resources) -- Resource types that can be publicly exposed on AWS
  * [aws_managed_policies](https://github.com/z0ph/aws_managed_policies) -- [MAMIP] Monitor AWS Managed IAM Policies Changes
  * [Security Tool Comparison](https://summitroute.github.io/aws_research/security_tool_comparison.html) -- Comparisons between various security tools.
  * [aws-public-account-ids](https://github.com/rupertbg/aws-public-account-ids) -- Publicly-listed AWS account IDs for easy lookup. Great for cleaning up false positives from unknown Account IDs in Cloudtrail.
  
## Other Awesome Lists
  * [toniblyx/my-arsenal-of-aws-security-tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools#other-interesting-toolscode)

### Offensive Security
  * [pacu](https://github.com/RhinoSecurityLabs/pacu) -- The AWS exploitation framework, designed for testing the security of Amazon Web Services environments.
  * [liquidswards](https://github.com/RyanJarv/liquidswards) -- Discover and maintain access to IAM roles.
  * [aws_pwn](https://github.com/dagrz/aws_pwn) -- A collection of AWS penetration testing junk.
  * [IAMFinder](https://github.com/prisma-cloud/IAMFinder) -- Enumerates and finds users and IAM roles in a target AWS account.
  * [enumerate-iam](https://github.com/andresriancho/enumerate-iam) -- Brute force enumeration of permissions associated with AWS credential set.
  * [endgame](https://github.com/brandongalbraith/endgame) -- An AWS Pentesting tool that lets you use one-liner commands to backdoor an AWS account's resources with a rogue AWS account - or share the resources with the entire internet 😈
  * [WeirdAAL](https://github.com/carnal0wnage/weirdAAL) -- WeirdAAL (AWS Attack Library)
  * [marionett](https://github.com/RyanJarv/marionett) -- Example of how an attacker might swap user data temporarily to execute arbitrary commands.

### Infrastructure as Code (IaC)
  * [terraformer](https://github.com/GoogleCloudPlatform/terraformer) -- CLI tool to generate terraform files from existing infrastructure (reverse Terraform). Infrastructure to Code
  * [former2](https://github.com/iann0036/former2) -- Generate CloudFormation / Terraform / Troposphere templates from your existing AWS resources.

### General Utilities
  * [coldsnap](https://github.com/awslabs/coldsnap) -- A command line interface for Amazon EBS snapshots
  * [lsh](https://github.com/tobilg/lsh) -- Run interactive shell commands on AWS Lambda
  * [dsnap](https://github.com/RhinoSecurityLabs/dsnap) -- Utility for downloading and mounting EBS snapshots using the EBS Direct API's  
  * [cognitocurl](https://github.com/nordcloud/cognitocurl) -- 🦉🤖Easily sign curl calls to API Gateway with Cognito authorization token.
* Offline Web Console's
  * [ScoutSuite](https://github.com/nccgroup/ScoutSuite) -- Multi-Cloud Security Auditing Tool
* Resource analysis
  * [awspx](https://github.com/FSecureLABS/awspx) -- Graph-based tool for visualizing effective access and resource relationships.    
  * [PMapper](https://github.com/nccgroup/PMapper) -- A tool for quickly evaluating IAM permissions in AWS.
  * [aws_public_ips](https://github.com/arkadiyt/aws_public_ips) -- Fetch all public IP addresses tied to your AWS account. Works with IPv4/IPv6, Classic/VPC networking, and across all AWS services
    * Fork that handles multiple regions: https://github.com/breser/aws_public_ips

### Resource DBs
  * [steampipe](https://steampipe.io/) -- The extensible SQL interface to your favorite cloud APIs.
  * [introspector](https://github.com/goldfiglabs/introspector) -- A schema and set of tools for using SQL to query cloud infrastructure
  * [cartography](https://github.com/lyft/cartography) -- Cartography is a Python tool that consolidates infrastructure assets and the relationships between them in an intuitive graph view powered by a Neo4j database.
  * [cloudquery](https://github.com/cloudquery/cloudquery) -- cloudquery transforms your cloud infrastructure into SQL or Graph database for easy monitoring, governance and security.

### Visual Resource Graphing
  * [cloudsplaining](https://github.com/salesforce/cloudsplaining) -- Cloudsplaining is an AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized report.
  * [cloudiscovery](https://github.com/Cloud-Architects/cloudiscovery) -- Discover resources in the cloud environment.
  * [cloudmapper](https://github.com/duo-labs/cloudmapper) -- Analyze your Amazon Web Services (AWS) environments
    * Note: Takes advantage of existing botocore definitions for discovery.
  * [hammer](https://github.com/dowjones/hammer) -- Dow Jones Hammer : Protect the cloud with the power of the cloud(AWS)
  * [cloudscout](https://github.com/SygniaLabs/security-cloud-scout) -- Identify and visualize cross platform attack paths, vulnerabilities, and enhance overall resilience.

### Linting/Static Analysis
  * [parliament](https://github.com/duo-labs/parliament) -- AWS IAM linting library

### Auditing
  * [rpCheckup](https://github.com/goldfiglabs/rpCheckup) -- rpCheckup is an AWS resource policy security checkup tool that identifies public, external account access, intra-org account access, and private resources.
  * [prowler](https://github.com/toniblyx/prowler) -- Best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.
  * [AWS Config](https://aws.amazon.com/config/) -- Lambda's that analyze resource state and changes, primarily in AWS but extensible
  * [cloudsploit](https://github.com/aquasecurity/cloudsploit) -- Cloud Security Posture Management (CSPM)
  * [smogcloud](https://github.com/BishopFox/smogcloud) -- Find cloud assets that no one wants exposed 🔎 ☁️

### Least privilege
  * [policy_sentry](https://github.com/salesforce/policy_sentry) -- IAM Least Privilege Policy Generator.
  * [repokid](https://github.com/Netflix/repokid) -- IAM least privilege service
  * [cloudtracker](https://github.com/duo-labs/cloudtracker) -- Finds over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies.
  * [iamlive](https://github.com/iann0036/iamlive) -- Generate a basic IAM policy from AWS client-side monitoring (CSM)
  * [aws-leastprivilege](https://github.com/iann0036/aws-leastprivilege) -- Generates an IAM policy for the CloudFormation service role that adheres to least privilege.

### Route53DB
  * [cloudjack](https://github.com/prevade/cloudjack) -- Route53/CloudFront Vulnerability Assessment Utility

### Vulnerable by design
  * [cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat) -- CloudGoat is Rhino Security Labs' "Vulnerable by Design" AWS deployment tool
  * [terragoat](https://github.com/bridgecrewio/terragoat) -- TerraGoat is Bridgecrew's "Vulnerable by Design" Terraform repository.
### SAML
  * [shimit](https://github.com/cyberark/shimit) -- A tool that implements the Golden SAML attack

### DNS
  * [subfinder](https://github.com/projectdiscovery/subfinder) -- Subfinder is a subdomain discovery tool that discovers valid subdomains for websites. Designed as a passive framework to be useful for bug bounties and safe for penetration testing.

### Subdomain Enumeration
  * [ctfr](https://github.com/UnaPibaGeek/ctfr) -- Abusing Certificate Transparency logs for getting HTTPS websites subdomains.

### Subdomain Takeover
  * [subdover](https://github.com/PushpenderIndia/subdover) -- Subdover is a MultiThreaded Subdomain Takeover Vulnerability Scanner Written In Python3
  * [cloudjack](https://github.com/prevade/cloudjack) -- Route53/CloudFront Vulnerability Assessment Utility
  * [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) -- "Can I take over XYZ?" — a list of services and how to claim (sub)domains with dangling DNS records.
  * [takeover](https://github.com/m4ll0k/takeover) -- Sub-Domain TakeOver Vulnerability Scanner
  * [SubOver](https://github.com/Ice3man543/SubOver) -- A Powerful Subdomain Takeover Tool

# Kubernetes
  * [cheatsheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)
  * [kube-hunter](https://github.com/aquasecurity/kube-hunter) -- Hunt for security weaknesses in Kubernetes clusters
  * [kubeaudit](https://github.com/Shopify/kubeaudit) -- kubeaudit helps you audit your Kubernetes clusters against common security controls
  * [kubiscan](https://github.com/cyberark/KubiScan) -- A tool to scan Kubernetes cluster for risky permissions
  * [kubesploit](https://github.com/cyberark/kubesploit) -- Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang, focused on containerized environments.
  * [kubernetes-rbac-audit](https://github.com/cyberark/kubernetes-rbac-audit) -- Tool for auditing RBACs in Kubernetes
  * [peirates](https://github.com/inguardians/peirates) -- Peirates - Kubernetes Penetration Testing tool
  * [cheatsheet](https://spacelift.io/blog/kubernetes-cheat-sheet) -- Kubernetes Cheat Sheet – 15 Kubectl Commands & Objects


  

# GCP
  * [pydevops](https://gist.github.com/pydevops/cffbd3c694d599c6ca18342d3625af97) -- gcp gcloud cheat sheet
  * [GCP-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation) -- A collection of GCP IAM privilege escalation methods documented by the Rhino Security Labs team.
  * [ScoutSuite](https://github.com/nccgroup/ScoutSuite) -- Multi-Cloud Security Auditing Tool
  * [terraformer](https://github.com/GoogleCloudPlatform/terraformer) -- CLI tool to generate terraform files from existing infrastructure (reverse Terraform). Infrastructure to Code
  * [gcp_enum](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp_enum) -- A simple bash script to enumerate Google Cloud Platform environments.
  * [gcp_misc](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp_misc) -- Miscellaneous tools related to attack operations in Google Cloud Platform.
  * [gcp_firewall_enum](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp_firewall_enum) -- Parse gcloud output to enumerate compute instances with network ports exposed to the Internet. Generates targeted nmap and masscan scripts based on the results.
  * [gcp_k8s_enum](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp_k8s_enum) -- Enumerate services exposed via GKE.


# Azure
  * [CRT](https://github.com/CrowdStrike/CRT) -- This tool queries the following configurations in the Azure AD/O365 tenant which can shed light on hard to find permissions and configuration settings in order to assist organizations in securing these environments.
  * [security-cloud-scout](https://github.com/SygniaLabs/security-cloud-scout) -- Cross-Cloud AWS/Azure
  * [how to applied purple teaming lab build on azure with terraform](https://www.blackhillsinfosec.com/how-to-applied-purple-teaming-lab-build-on-azure-with-terraform/)
  * [ScoutSuite](https://github.com/nccgroup/ScoutSuite) -- Multi-Cloud Security Auditing Tool

# Other

### Secret Scanning
  * [DumpsterDiver](https://github.com/securing/DumpsterDiver) -- Tool to search secrets in various filetypes.
  * [ebs-direct-sec-tools](https://github.com/crypsisgroup/ebs-direct-sec-tools) -- Uses EBS Direct API to scan blocks for secrets

### Terraform
  * Terraform Static Analysis
    * [checkov](https://github.com/bridgecrewio/checkov) -- Prevent cloud misconfigurations during build-time for Terraform, Cloudformation, Kubernetes, Serverless framework and other infrastructure-as-code-languages with Checkov by Bridgecrew.
    * [terrascan](https://github.com/accurics/terrascan)
      * Related: [KaiMonkey](https://github.com/accurics/KaiMonkey)  
    * [tfsec](https://github.com/aquasecurity/tfsec) -- Security scanner for your Terraform code
    * [kics](https://github.com/Checkmarx/kics) -- Find security vulnerabilities, compliance issues, and infrastructure misconfigurations early in the development cycle of your infrastructure-as-code with KICS by Checkmarx.
  * [AirIAM](https://github.com/bridgecrewio/AirIAM) -- Least privilege AWS IAM Terraformer.
  * [terraform_aws_scp](https://github.com/ScaleSec/terraform_aws_scp) -- AWS Organizations Service Control Policies (SCPs) for Terraform.
  * [terraformer](https://github.com/GoogleCloudPlatform/terraformer) -- CLI tool to generate terraform files from existing infrastructure (reverse Terraform). Infrastructure to Code

### Containers
  * [deepce](https://github.com/stealthcopter/deepce/) -- Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE).
  * [ccat](https://github.com/RhinoSecurityLabs/ccat) -- Cloud Container Attack Tool (CCAT) is a tool for testing security of container environments.
  * [trivy](https://github.com/aquasecurity/trivy) -- Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues

### Open Policy Agent (OPA)
  * [opa](https://github.com/open-policy-agent/opa) -- An open source, general-purpose policy engine.
  * [fregot](https://github.com/fugue/fregot) -- Alternative REPL to OPA's built-in interpreter.
  * [policy-hub-cli](https://github.com/policy-hub/policy-hub-cli) -- CLI for searching Rego policies
  * [conftest](https://github.com/open-policy-agent/conftest) -- Write tests against structured configuration data using the Open Policy Agent Rego query language

### Misc
  * [website-openid-proxy](https://github.com/wolfeidau/website-openid-proxy) -- This service provides authenticated access to a static website hosted in an s3 bucket.
  * [Config Conformance Packs](https://asecure.cloud/l/p_conformance_packs/)
  * [detect-secrets](https://github.com/Yelp/detect-secrets) -- An enterprise friendly way of detecting and preventing secrets in code.

### Non-CloudSec Stuff (TODO: move this elsewhere)
  * [proxify](https://github.com/projectdiscovery/proxify) -- Swiss Army knife Proxy tool for HTTP/HTTPS traffic capture, manipulation, and replay on the go.
  * [CloudFail](https://github.com/m0rtem/CloudFail) -- Utilize misconfigured DNS and old database records to find hidden IP's behind the CloudFlare network.
  * [chalice](https://github.com/aws/chalice) -- Python Serverless Microframework for AWS
  * [placebo](https://github.com/garnaat/placebo) -- Make boto3 calls that look real but have no effect.
  * [serverlessish](https://github.com/glassechidna/serverlessish) -- Run the same Docker images in AWS Lambda and AWS ECS
  * [BloodHound](https://github.com/BloodHoundAD/BloodHound) -- Six Degrees of Domain Admin
  * [ProcMon-for-Linux](https://github.com/Sysinternals/ProcMon-for-Linux) -- Procmon is a Linux reimagining of the classic Procmon tool from the Sysinternals suite of tools for Windows. Procmon provides a convenient and efficient way for Linux developers to trace the syscall activity on the system.
  * [exec-template](https://github.com/groob/exec-template) -- Super simple go templater.
  * [leapp](https://github.com/Noovolari/leapp) -- Potential alternative to aws-vault
