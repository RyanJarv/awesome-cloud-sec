# awesome-aws-sec
Awesome list for cloud (mostly AWS), security, pentesting related projects and libraries.

NOTE: This isn't an endorsement of any of these projects. I'm mostly using this as a way to keep track of interesting projects I come across.


* AWS
  * Offensive Security
    * General
      * [aws_pwn](https://github.com/dagrz/aws_pwn) -- A collection of AWS penetration testing junk.
    * IAM
      * [IAMFinder](https://github.com/prisma-cloud/IAMFinder) -- Enumerates and finds users and IAM roles in a target AWS account.
      * [enumerate-iam](https://github.com/andresriancho/enumerate-iam) -- Brute force enumeration of permissions associated with AWS credential set.
  * General Utilities
    * [coldsnap](https://github.com/awslabs/coldsnap) -- A command line interface for Amazon EBS snapshots
    * [lsh](https://github.com/tobilg/lsh) -- Run interactive shell commands on AWS Lambda
  * Resource analysis
    * [awspx](https://github.com/FSecureLABS/awspx) -- Graph-based tool for visualizing effective access and resource relationships.
    * [cloudmapper](https://github.com/duo-labs/cloudmapper) -- [Graphing] Analyze your Amazon Web Services (AWS) environments
    * [cloudiscovery](https://github.com/Cloud-Architects/cloudiscovery) -- [Graphing] Discover resources in the cloud environment.
      * Note: Takes advantage of existing botocore definitions for discovery.
    * [PMapper](https://github.com/nccgroup/PMapper) -- A tool for quickly evaluating IAM permissions in AWS.
    * [ScoutSuite](https://github.com/nccgroup/ScoutSuite) -- Multi-Cloud Security Auditing Tool
  * Linting/Static Analysis
      * [parliament](https://github.com/duo-labs/parliament) -- AWS IAM linting library
  * Auditing/Least privilege
    * General
      * [prowler](https://github.com/toniblyx/prowler) -- Best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.
    * IAM
      * [policy_sentry](https://github.com/salesforce/policy_sentry) -- IAM Least Privilege Policy Generator.
      * [repokid](https://github.com/Netflix/repokid) -- IAM least privilege service
      * [AirIAM](https://github.com/bridgecrewio/AirIAM) -- Least privilege AWS IAM Terraformer.
      * [cloudtracker](https://github.com/duo-labs/cloudtracker) -- Finds over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies.

* Other
 * Azure
   * [CRT](https://github.com/CrowdStrike/CRT) -- This tool queries the following configurations in the Azure AD/O365 tenant which can shed light on hard to find permissions and configuration settings in order to assist organizations in securing these environments.

 * Containers
   * [deepce](https://github.com/stealthcopter/deepce/) -- Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE).

 * Terraform Static Analysis
     * [terrascan](https://github.com/accurics/terrascan)
       * Related: [KaiMonkey](https://github.com/accurics/KaiMonkey)    

 * Networking
   * [proxify](https://github.com/projectdiscovery/proxify) -- Swiss Army knife Proxy tool for HTTP/HTTPS traffic capture, manipulation, and replay on the go.
   * [CloudFail](https://github.com/m0rtem/CloudFail) -- Utilize misconfigured DNS and old database records to find hidden IP's behind the CloudFlare network.

 * Development
   * [chalice](https://github.com/aws/chalice) -- Python Serverless Microframework for AWS
   * [placebo](https://github.com/garnaat/placebo) -- Make boto3 calls that look real but have no effect.
   * [serverlessish](https://github.com/glassechidna/serverlessish) -- Run the same Docker images in AWS Lambda and AWS ECS

 * Infrastructure
   * [terraform_aws_scp](https://github.com/ScaleSec/terraform_aws_scp) -- AWS Organizations Service Control Policies (SCPs) for Terraform.
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


