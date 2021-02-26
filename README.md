# awesome-aws-sec
Awesome list for cloud (mostly AWS), security, pentesting related projects and libraries.

NOTE: This isn't an endorsement of any of these projects. I'm mostly using this as a way to keep track of interesting projects I come across.


* AWS
  * Info
    * [aws_exposable_resources](https://github.com/SummitRoute/aws_exposable_resources) -- Resource types that can be publicly exposed on AWS
    * [aws_managed_policies](https://github.com/z0ph/aws_managed_policies) -- [MAMIP] Monitor AWS Managed IAM Policies Changes
    * [Security Tool Comparison](https://summitroute.github.io/aws_research/security_tool_comparison.html) -- Comparisons between various security tools.
  * Offensive Security
    * [pacu](https://github.com/RhinoSecurityLabs/pacu) -- The AWS exploitation framework, designed for testing the security of Amazon Web Services environments.
    * [aws_pwn](https://github.com/dagrz/aws_pwn) -- A collection of AWS penetration testing junk.
    * [IAMFinder](https://github.com/prisma-cloud/IAMFinder) -- Enumerates and finds users and IAM roles in a target AWS account.
    * [enumerate-iam](https://github.com/andresriancho/enumerate-iam) -- Brute force enumeration of permissions associated with AWS credential set.
  * General Utilities
    * [coldsnap](https://github.com/awslabs/coldsnap) -- A command line interface for Amazon EBS snapshots
    * [lsh](https://github.com/tobilg/lsh) -- Run interactive shell commands on AWS Lambda
  * Offline Web Console's
    * [ScoutSuite](https://github.com/nccgroup/ScoutSuite) -- Multi-Cloud Security Auditing Tool
  * Resource analysis
    * [awspx](https://github.com/FSecureLABS/awspx) -- Graph-based tool for visualizing effective access and resource relationships.    
    * [PMapper](https://github.com/nccgroup/PMapper) -- A tool for quickly evaluating IAM permissions in AWS.
  * Visual Resource Graphing
    * [cloudsplaining](https://github.com/salesforce/cloudsplaining) -- Cloudsplaining is an AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized report.
    * [cloudiscovery](https://github.com/Cloud-Architects/cloudiscovery) -- [Graphing] Discover resources in the cloud environment.
    * [cloudmapper](https://github.com/duo-labs/cloudmapper) -- [Graphing] Analyze your Amazon Web Services (AWS) environments
      * Note: Takes advantage of existing botocore definitions for discovery.
    * [cartography](https://github.com/lyft/cartography) -- Cartography is a Python tool that consolidates infrastructure assets and the relationships between them in an intuitive graph view powered by a Neo4j database.
  * Linting/Static Analysis
      * [parliament](https://github.com/duo-labs/parliament) -- AWS IAM linting library
  * Auditing
    * [prowler](https://github.com/toniblyx/prowler) -- Best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.
  * Least privilege
    * [policy_sentry](https://github.com/salesforce/policy_sentry) -- IAM Least Privilege Policy Generator.
    * [repokid](https://github.com/Netflix/repokid) -- IAM least privilege service
    * [cloudtracker](https://github.com/duo-labs/cloudtracker) -- Finds over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies.
    * [iamlive](https://github.com/iann0036/iamlive) -- Generate a basic IAM policy from AWS client-side monitoring (CSM)
    * [aws-leastprivilege](https://github.com/iann0036/aws-leastprivilege) -- Generates an IAM policy for the CloudFormation service role that adheres to least privilege.

* Terraform
  * Terraform Static Analysis
    * [checkov](https://github.com/bridgecrewio/checkov) -- Prevent cloud misconfigurations during build-time for Terraform, Cloudformation, Kubernetes, Serverless framework and other infrastructure-as-code-languages with Checkov by Bridgecrew.
    * [terrascan](https://github.com/accurics/terrascan)
      * Related: [KaiMonkey](https://github.com/accurics/KaiMonkey)  
  * [AirIAM](https://github.com/bridgecrewio/AirIAM) -- Least privilege AWS IAM Terraformer.
  * [terraform_aws_scp](https://github.com/ScaleSec/terraform_aws_scp) -- AWS Organizations Service Control Policies (SCPs) for Terraform.
  


* Secret Scanning
  * [DumpsterDiver](https://github.com/securing/DumpsterDiver) -- Tool to search secrets in various filetypes.
  * [ebs-direct-sec-tools(https://github.com/crypsisgroup/ebs-direct-sec-tools) -- Uses EBS Direct API to scan blocks for secrets

 * Azure
   * [CRT](https://github.com/CrowdStrike/CRT) -- This tool queries the following configurations in the Azure AD/O365 tenant which can shed light on hard to find permissions and configuration settings in order to assist organizations in securing these environments.

 * Containers
   * [deepce](https://github.com/stealthcopter/deepce/) -- Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE).
   * [ccat](https://github.com/RhinoSecurityLabs/ccat) -- Cloud Container Attack Tool (CCAT) is a tool for testing security of container environments.

 * Networking
   * [proxify](https://github.com/projectdiscovery/proxify) -- Swiss Army knife Proxy tool for HTTP/HTTPS traffic capture, manipulation, and replay on the go.
   * [CloudFail](https://github.com/m0rtem/CloudFail) -- Utilize misconfigured DNS and old database records to find hidden IP's behind the CloudFlare network.

 * Development
   * [chalice](https://github.com/aws/chalice) -- Python Serverless Microframework for AWS
   * [placebo](https://github.com/garnaat/placebo) -- Make boto3 calls that look real but have no effect.
   * [serverlessish](https://github.com/glassechidna/serverlessish) -- Run the same Docker images in AWS Lambda and AWS ECS

 * Infrastructure
   * [website-openid-proxy](https://github.com/wolfeidau/website-openid-proxy) -- https://github.com/wolfeidau/website-openid-proxy

 * Config
   * https://asecure.cloud/l/p_conformance_packs/

 * Learning Environments
   * https://www.blackhillsinfosec.com/how-to-applied-purple-teaming-lab-build-on-azure-with-terraform/

 * Opa
   * [opa](https://github.com/open-policy-agent/opa) -- An open source, general-purpose policy engine.
   * [fregot](https://github.com/fugue/fregot) -- Alternative REPL to OPA's built-in interpreter.
   * [policy-hub-cli](https://github.com/policy-hub/policy-hub-cli) -- CLI for searching Rego policies

 * Other
   * [exec-template](https://github.com/groob/exec-template) -- Super simple go templater.
   * [leapp](https://github.com/Noovolari/leapp) -- Potential alternative to aws-vault


