import boto3, os, configparser, logging, argparse, sys, ipaddress, yaml, json, secrets, string, time
from requests import get
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient

# GLOBALS
ARGS = {}
LOGGER = logging.getLogger()
DEFAULT_TEMPLATE_PATH = f"{os.getcwd()}{os.sep}cloud-formation-template.yml"
DEFAULT_SCRIPT_PATH = f"{os.getcwd()}{os.sep}install-software.sh"
AWS = boto3.Session()
CLOUD_FORMATION = AWS.client('cloudformation')
SSH_CLIENT = SSHClient()
SSH_CLIENT.set_missing_host_key_policy(AutoAddPolicy())


class LoggerColourFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(levelname)s: %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        logFmt = self.FORMATS[record.levelno]
        formatter = logging.Formatter(logFmt)
        return formatter.format(record)


def getIpCidr():
    """
    Gets the user's current public IP address as a default for the whitelist
    """
    try:
        return f"{get('https://api.ipify.org').content.decode('utf8')}/32"
    except Exception as e:
        LOGGER.exception(f"FAILED to get the user's current public IP address with ipify:\n{e}")


def parseArgs():
    """
    Parses and validates the arguments given by the user and returns a dictionary containing them. Also sets up logging
    """
    parser = argparse.ArgumentParser(
        prog="jump4joy",
        description="An AWS EC2 jumpbox/vpnbox/proxybox deployer",
        epilog="Authored by @M-Davies. Please submit feedback and bug reports to https://github.com/M-Davies/jump4joy"
    )
    parser.add_argument(
        "-p", "--profile",
        help="The profile to use in your AWS credentials file. Defaults to the 'default' profile",
        default="default",
        required=False
    )
    parser.add_argument(
        "-r", "--region",
        help="The region to create your jumpbox in. The credentials you provide should have access to the region you specify here",
        required=False
    )
    parser.add_argument(
        "-i", "--access-key-id",
        help="AWS Access Key ID with read & write access to CloudFormation and EC2.",
        required=False
    )
    parser.add_argument(
        "-k", "--secret-access-key",
        help="AWS Secret key of the key you provided for (-i)",
        required=False
    )
    parser.add_argument(
        "-s", "--services",
        help="The forwarding proxy or VPN services to install on the box. By default, this includes http and socks proxies, as well as an OpenVPN server. Supply a different set of services here if you so choose, seperated by spaces (e.g. '--services http socks openvpn')",
        required=False,
        nargs="+",
        choices=["http", "socks", "openvpn"],
        default=["http", "socks", "openvpn"]
    )
    parser.add_argument(
        "-t", "--template-file",
        help=f"Custom CloudFormation template file path. Defaults to the provided template ({os.getcwd()}{os.sep}cloud-formation-template.yml)",
        required=False,
        default=DEFAULT_TEMPLATE_PATH
    )
    parser.add_argument(
        "-f", "--install-script",
        help=f"Custom install script to run on the EC2 box. Defaults to the provided template ({os.getcwd()}{os.sep}install-software.sh)",
        required=False,
        default=DEFAULT_SCRIPT_PATH
    )
    parser.add_argument(
        "-c", "--disable-colours",
        help="Disables colouring of log output. You might find this option useful if you're exclusively writing to a log file or on Windows.",
        required=False,
        action="store_true",
        default=False
    )
    parser.add_argument(
        "--timeout",
        help="Timeout for the software install script in seconds. Defaults to 1800 (30 minutes)",
        required=False,
        type=float,
        default=1800.0
    )
    parser.add_argument(
        "--whitelisted-ip-range",
        help="Whitelisted Cidr IP address range that can access the jumpbox services. Must be in Cidr format (e.g. '183.231.111.41/32' or '0.0.0.0/0' for publicly accessible). Defaults to your public IP.",
        required=False,
        default=getIpCidr(),
    )
    parser.add_argument(
        "--http-user",
        help="Username of the HTTP proxy user (password will be generated automatically). Defaults to 'httpuser123'",
        required=False,
        default="httpuser123"
    )
    parser.add_argument(
        "--socks-user",
        help="Username of the SOCKS proxy user (password will be generated automatically). Defaults to 'socksuser123'",
        required=False,
        default="socksuser123"
    )
    parser.add_argument(
        "--openvpn-user",
        help="Username of the OpenVPN user (password will be generated automatically). Defaults to 'openvpnuser123'",
        required=False,
        default="openvpnuser123"
    )
    parser.add_argument(
        "-v", "--verbose",
        help="Increase verbosity, will report progress for each interaction rather than just warnings and errors",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-q", "--quiet",
        help="No output to the console (log file output will still be present if specified), only errors will be shown",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-l", "--log",
        help="Produces a log file of verbose and non-verbose debug information.",
        required=False
    )
    localArgs = parser.parse_args()

    # Setup logging
    if localArgs.verbose is True:
        LOGGER.setLevel(logging.INFO)
    else:
        LOGGER.setLevel(logging.WARN)
    
    if localArgs.disable_colours is True:
        logFormat = logging.Formatter("%(asctime)s: %(levelname)s: %(message)s")
    else:
        logFormat = LoggerColourFormatter()
    
    if localArgs.quiet is False:
        LOG_OUTPUT_HANDLER = logging.StreamHandler(sys.stderr)
        LOG_OUTPUT_HANDLER.setFormatter(logFormat)
        LOGGER.addHandler(LOG_OUTPUT_HANDLER)
    
    if localArgs.log is not None:
        LOG_FILE_HANDLER = logging.FileHandler(filename=localArgs.log, encoding="utf-8", mode="a")
        LOG_FILE_HANDLER.setFormatter(logFormat)
        LOGGER.addHandler(LOG_FILE_HANDLER)

    # Check whitelist is a CIDR address
    try:
        ipaddress.ip_network(localArgs.whitelisted_ip_range)
    except ValueError:
        LOGGER.exception(f"{localArgs.whitelisted_ip_range} is an invalid Cidr IP address format. All whitelisted IPs must be provided in Cidr format (e.g. '183.231.111.41/32')")

    # Check if cloud template exists
    if os.path.exists(localArgs.template_file) is False:
        LOGGER.exception(f"Could not find cloud formation template file at {localArgs.file}")

    return localArgs


def createSession():
    """
    Creates and returns an AWS session (unknown if it's authenticated or not yet)
    """
    # Get config if it exists
    credentialsPath = os.path.join(os.path.expanduser("~/.aws"), "credentials")
    if os.path.exists(credentialsPath):
        # Read AWS credentials from the cred file
        LOGGER.info(f"Found AWS credentials file at ~{os.sep}.aws{os.sep}credentials")
        awsConfig = configparser.ConfigParser().read(credentialsPath)
        accessKeyId = awsConfig.get(ARGS.profile, "aws_access_key_id")
        secretAccessKey = awsConfig.get(ARGS.profile, "aws_secret_access_key")
        region = awsConfig.get(ARGS.profile, "region")

    # Overwrite with custom values if they exist
    if ARGS.access_key_id is not None:
        accessKeyId = ARGS.access_key_id
    if ARGS.secret_access_key is not None:
        secretAccessKey = ARGS.secret_access_key
    if ARGS.region is not None:
        region = ARGS.region

    return boto3.Session(
        aws_access_key_id=accessKeyId,
        aws_secret_access_key=secretAccessKey,
        region_name=region
    )


def generatePassword():
    """
    Generates a secure password
    """
    return "".join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(20))


def deployCloudTemplate():
    """
    Deploys the provided cloud formation template into the AWS environment and returns it's ID
    """
    LOGGER.info("Parsing provided cloud formation template file...")
    # Load into JSON format
    yamlContent = ""
    try:
        with open(ARGS.template_file, "r") as templateFile:
            yamlContent = yaml.load(templateFile)
    except OSError as e:
        LOGGER.exception(f"FAILED to open cloud formation template file at {ARGS.template_file}\n{e}")
    jsonContent = json.dumps(yamlContent)

    # Generate stack name
    LOGGER.info("Generating cloud formation stack name...")
    stackId = 1
    newStackName = f"jump4joyStack{stackId}"
    stackNames = [stack["StackName"] for stack in CLOUD_FORMATION.list_stacks()["StackSummaries"]]
    while newStackName in stackNames:
        stackId += 1
        newStackName = f"jump4joyStack{stackId}"
    
    # Create stack
    LOGGER.info(f"Creating jump4joy cloud formation stack '{newStackName}'...")
    try:
        return CLOUD_FORMATION.create_stack(
            StackName=newStackName,
            TemplateBody=jsonContent,
            Parameters=[{
                "EC2Name": f"{newStackName}EC2Box",
                "KeyPairName": f"{newStackName}KeyPair",
                "SecurityGroupName": f"{newStackName}SecurityGroup",
                "Cidr": ARGS.whitelisted_ip_range,
            }],
            TimeoutInMinutes=5,
            OnFailure="DELETE",
            EnableTerminationProtection=False
        )["StackId"]
    except Exception as e:
        LOGGER.exception(f"FAILED to create cloud stack '{newStackName}':\n{e}")


def loginEC2Box(stackId: str):
    """
    Starts and returns a SSH session inside the EC2 box
    """
    # Get keypair id
    LOGGER.info("Getting ID of EC2 keypair resource...")
    try:
        keyPairId = CLOUD_FORMATION.describe_stack_resources(StackName=stackId, LogicalResourceId="KeyPair")["StackResources"][0]["PhysicalResourceId"]
    except Exception as e:
        LOGGER.exception(f"FAILED to retrieve physical resource ID of key pair for {stackId}\n{e}")
    
    # Get private key
    LOGGER.info("Retrieving SSH private key for EC2 box from Systems Manager...")
    ssm = boto3.client('ssm')
    try:
        ec2PrivateKey = ssm.get_parameter(Name=f"/ec2/keypair/{keyPairId}", WithDecryption=False)["Parameter"]["Value"]
    except Exception as e:
        LOGGER.info(f"FAILED to get private key '/ec2/keypair/{keyPairId}' value\n{e}")
    
    # Establish connection
    ec2Ip = getStackDetails(stackId)["Outputs"][0]["OutputValue"]
    LOGGER.info(f"Connecting to EC2 box at {ec2Ip}...")
    try:
        SSH_CLIENT.connect(
            hostname=ec2Ip,
            username="ubuntu",
            pkey=ec2PrivateKey
        )
        return ec2Ip
    except Exception as e:
        LOGGER.exception(f"FAILED to establish ssh connection to EC2 box at {ec2Ip}\n{e}")


def setupEC2Box():
    """
    Installs and starts the necessary software on the EC2 box. Returns the exit code of the install script
    """
    SCRIPT_PATH = "/home/ubuntu/install-script.sh"
    # Transfer over install script
    LOGGER.info(f"Copying software install script at {ARGS.install_script} to {SCRIPT_PATH}")
    SCP = SCPClient(SSH_CLIENT.get_transport())
    scriptResult = 1
    try:
        if os.path.exists(ARGS.install_script):
            SCP.put(files=ARGS.install_script, remote_path=SCRIPT_PATH)
        else:
            LOGGER.exception(f"Could not find install-script.sh file at {ARGS.install_script}")
        
        # Generate service credentials
        httpPassword = generatePassword()
        openvpnPassword = generatePassword()
        socksPassword = generatePassword()

        # Run install script (30min timeout)
        LOGGER.info(f"Executing install script {SCRIPT_PATH}")
        script = f"""
        chmod +x {SCRIPT_PATH} && HTTP_USER={ARGS.http_user} HTTP_PASSWORD={httpPassword} OPENVPN_USER={ARGS.openvpn_user} OPENVPN_PASSWORD={openvpnPassword} SOCKS_USER={ARGS.socks_user} SOCKS_PASSWORD={socksPassword} bash {SCRIPT_PATH}
        """
        stdin, stdout, stderr = SSH_CLIENT.exec_command(command=script, timeout=ARGS.timeout)
        LOGGER.info(f"STDOUT:\n{stdout.readlines()}")
        LOGGER.info(f"STDERR:\n{stderr.readlines()}")

        # Get result
        scriptResult = stdout.channel.recv_exit_status()
    except Exception as e:
        LOGGER.exception(f"FAILED to copy over and/or run the install script\n{e}")
    finally:
        LOGGER.info("Closing SSH connections...")
        SCP.close()
        SSH_CLIENT.close()

    return {
        "code": scriptResult,
        "passwords": {
            "http": httpPassword,
            "openvpn": openvpnPassword,
            "socks": socksPassword,
        }
    }


def getStackDetails(stackId: str):
    """
    Returns the details of the created cloud formation stack
    """
    try:
        return CLOUD_FORMATION.describe_stacks(StackName=stackId)["Stacks"][0]
    except Exception as e:
        LOGGER.info(f"FAILED to get details for stack '{stackId}':\n{e}")


def main():
    """
    Entrypoint of the main program
    """
    global AWS, CLOUD_FORMATION

    # Create framework of login session
    AWS = createSession()

    # Verify session is valid
    caller = None
    try:
        sts = AWS.client("sts")
        caller = sts.get_caller_identity()
    except Exception as e:
        LOGGER.exception(f"FAILED to authenticate to AWS:\n{e}")
    
    LOGGER.info(f"Successfully authenticated to AWS as {caller['Arn']}")
    
    # Start cloud formation build
    CLOUD_FORMATION = AWS.client("cloudformation")
    stackId = deployCloudTemplate()
    # Wait for completion
    stackStatus = getStackDetails(stackId)["StackStatus"]
    while stackStatus != "CREATE_COMPLETE":
        LOGGER.info(f"Stack {stackId} is still building. Checking status again in 10 seconds...")
        time.sleep(10)
        stackStatus = getStackDetails(stackId)["StackStatus"]
    LOGGER.info(f"Successfully created jump4joy cloud formation stack '{stackId}'!")

    # Login to EC2 box
    ec2Ip = loginEC2Box(stackId)
    LOGGER.info(f"Connected to EC2 box {ec2Ip}")

    # Setup EC2 box
    outputs = setupEC2Box()
    if outputs["code"] != 0:
        LOGGER.warning(f"Install script failed to sucessfully complete execution (exit code = {outputs['code']}). Please see the logs above for the reasons why.")
    else:
        LOGGER.info("Printing credentials for services. THESE WILL NOT BE RECORDED IN LOGS, PLEASE SAVE THEM SECURELY NOW:")
        print(f"HTTP Proxy Credentials (<username>:<password>) = '{ARGS.http_user}:{outputs['passwords']['http']}'")
        print(f"OpenVPN Credentials (<username>:<password>) = '{ARGS.openvpn_user}:{outputs['passwords']['openvpn']}'")
        print(f"SOCKS5 Proxy Credentials (<username>:<password>) = '{ARGS.socks_user}:{outputs['passwords']['socks']}'")
    LOGGER.info(f"All stages complete. Proxy is available at {ec2Ip}.")
    print(f"All stages complete. Proxy is available at {ec2Ip}.")


if __name__ == "__main__":
    ARGS = parseArgs()
    main()
