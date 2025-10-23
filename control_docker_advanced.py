import paramiko
from time import sleep
import os.path
import sys
 
def get_ssh_key_path(key_file):
    """Handle path expansion and validation"""
    expanded_path = os.path.expanduser(key_file)
    if not os.path.exists(expanded_path):
        raise FileNotFoundError(f"SSH key file not found at: {expanded_path}")
    if not os.access(expanded_path, os.R_OK):
        raise PermissionError(f"SSH key file not readable: {expanded_path}")
    return expanded_path
 
def check_docker_image_exists(ssh, image_name):
    """Check if Docker image exists locally"""
    stdin, stdout, stderr = ssh.exec_command(f"docker images -q {image_name}")
    image_id = stdout.read().decode().strip()
    return bool(image_id)
 
def install_docker(ssh):
    commands = [
        'sudo apt-get update',
        'sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common',
        'curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -',
        'sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"',
        'sudo apt-get update',
        'sudo apt-get install -y docker-ce docker-ce-cli containerd.io',
        'sudo usermod -aG docker $USER',
        'newgrp docker'  # This won't work in SSH - need logout/login
    ]
    
    for cmd in commands:
        print(f"\n>>> Executing: {cmd}")
        stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
        exit_status = stdout.channel.recv_exit_status()
        
        # Print real-time output
        while True:
            line = stdout.readline()
            if not line:
                break
            print(line.strip())
        
        errors = stderr.read().decode()
        if errors:
            print(f"ERRORS: {errors}")
        
        if exit_status != 0:
            print(f"Command failed with exit status {exit_status}")
        sleep(1)
 
def stream_command_output(ssh, command, timeout=300):
    """Execute command and stream output in real-time"""
    print(f"\n=== Executing: {command} ===")
    stdin, stdout, stderr = ssh.exec_command(command, get_pty=True)
    
    # Read output in real-time
    while True:
        if stdout.channel.exit_status_ready():
            break
            
        # Print stdout
        while stdout.channel.recv_ready():
            print(stdout.channel.recv(1024).decode(), end="")
            
        # Print stderr
        while stderr.channel.recv_stderr_ready():
            print(stderr.channel.recv_stderr(1024).decode(), end="", file=sys.stderr)
        
        sleep(0.1)
    
    exit_status = stdout.channel.recv_exit_status()
    print(f"\n=== Command completed with exit status {exit_status} ===")
    return exit_status
 
def build_docker_client(workflow, args):
    base_cmd = (
        f"docker run -it --rm --name ve3c-client "
        f"bwbgv/ve3c-image client "
        f"--policy_host={args['policy_host']} "
        f"--server_app_host={args['server_app_host']} "
        f"--analysis_type={workflow}"
    )
    
    if workflow == "sequence_quality":
        return (
            f"{base_cmd} "
            f"--dataset_file={args['dataset_file']} "
            f"--parameters={args['parameters']} "
            f"--threads={args.get('threads', 2)}"
        )
    elif workflow == "read_alignment":
        return (
            f"{base_cmd} "
            f"--reference_genome={args['reference_genome']} "
            f"--paired_file_1={args['paired_file_1']} "
            f"--paired_file_2={args['paired_file_2']}"
        )
    elif workflow in ["indel_calling", "snp_calling"]:
        return (
            f"{base_cmd} "
            f"--reference_genome={args['reference_genome']} "
            f"--dataset_file={args['dataset_file']}"
        )
    else:
        raise ValueError(f"Unknown workflow: {workflow}")
 
 
def run_certifier_vm(ip, key_file, vm_type, workflow=None, cpu=2, mem_gb=4, workflow_args=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    resolved_key_path = get_ssh_key_path(key_file)
    
    print(f"Connecting to {ip} using key: {resolved_key_path}")
    ssh.connect(ip, username='ubuntu', key_filename=resolved_key_path)
    
    try:
        ssh.connect(ip, username='ubuntu', key_filename=key_file)
        
        # 1. Check/Install Docker
        print("\n=== Checking Docker Installation ===")
        stdin, stdout, stderr = ssh.exec_command('docker --version', get_pty=True)
        docker_version = stdout.read().decode().strip()
        
        if not docker_version.startswith('Docker version'):
            print("Docker not found, installing...")
            install_docker(ssh)
        else:
            print(f"Docker already installed: {docker_version}")
        
        # 2. Clean up and pull image
        image_name = "bwbgv/ve3c-image:latest"
        print(f"\n=== Checking for existing Docker image: {image_name} ===")
        
        if check_docker_image_exists(ssh, image_name):
            print("Image already exists locally, skipping pull")
        else:
            print("Image not found locally, pulling...")
            stream_command_output(ssh, f"docker pull {image_name}")
        
        # 3. Run appropriate service
        if vm_type.lower() == 'server':
            print("\n=== Starting Server ===")
            # Clean up any existing server
            # stream_command_output(ssh, "docker rm -f ve3c-server || true")
            
            cmd = (
                f"docker network create --driver bridge certifier-net && "
                f"docker run -d --name ve3c-server --network host "
                f"--cpus={cpu} --memory={mem_gb}g "
                f"-p 8123:8123 -p 8124:8124 "
                f"bwbgv/ve3c-image server "
                f"--host=0.0.0.0 --policy_host=0.0.0.0 --server_app_host=0.0.0.0"
            )
            stream_command_output(ssh, cmd)
            
            # Monitor server logs
            print("\n=== Server Logs (Ctrl+C to stop monitoring) ===")
            try:
                stdin, stdout, stderr = ssh.exec_command("docker logs -f ve3c-server", get_pty=True)
                while True:
                    print(stdout.readline(), end="")
            except KeyboardInterrupt:
                print("\nStopped monitoring server logs")
                
        elif vm_type.lower() == 'client':
            if not workflow:
                raise ValueError("Workflow must be specified for client VM")
                
            print(f"\n=== Starting Client ({workflow} workflow) ===")
            cmd = build_docker_client(workflow, workflow_args)
            exit_code = stream_command_output(ssh, cmd)
            
            if exit_code != 0:
                print(f"\n⚠️ Client workflow failed with exit code {exit_code}")
            else:
                print(f"\n✅ Client workflow completed successfully")
                
        else:
            raise ValueError("vm_type must be either 'server' or 'client'")
            
    except Exception as e:
        print(f"\n❌ Error on {ip}: {str(e)}")
    finally:
        ssh.close()
        print("\n=== SSH Connection Closed ===")
 
    
# Example usage for different workflows
if __name__ == "__main__":
    common_args = {
        'policy_host': '172.31.20.155',
        'server_app_host': '172.31.20.155'
    }
    
    # 1. Start server
    # run_certifier_vm(
    #     ip='98.81.94.29',
    #     key_file='/Users/bishwaswagle/.ssh/CertifierBiswasMarc24.pem',
    #     vm_type='server'
    # )
    
    # 2. Run FastQC client
    # run_certifier_vm(
    #     ip='34.227.74.118',
    #     key_file='/Users/bishwaswagle/.ssh/CertifierBiswasMarc24.pem',
    #     vm_type='client',
    #     workflow='sequence_quality',
    #     workflow_args={
    #         **common_args,
    #         'dataset_file': '/root/SRR2584863_1.fastq',
    #         'parameters': '--quiet',
    #         'threads': 2
    #     }
    # )
    
    # 3. Run Read Alignment client
    run_certifier_vm(
        ip='34.227.74.118',
        key_file='/Users/bishwaswagle/.ssh/CertifierBiswasMarc24.pem',
        vm_type='client',
        workflow='read_alignment',
        workflow_args={
            **common_args,
            'reference_genome': '/root/ecoli_reference.fa',
            'paired_file_1': '/root/SRR2584863_1.fastq',
            'paired_file_2': '/root/SRR2584863_2.fastq'
        }
    )
    
    # # 4. Run Indel Calling client
    # run_certifier_vm(
    #     ip='34.227.74.118',
        # key_file='~/.ssh/CertifierBiswasMarc24.pem',
    #     vm_type='client',
    #     workflow='indel_calling',
    #     workflow_args={
    #         **common_args,
    #         'reference_genome': '/root/ecoli_reference.fa',
    #         'dataset_file': '/root/example.rg.bam'
    #     }
    # )
 
    # # 5. Run SNP Calling client
    # run_certifier_vm(
    #     ip='34.227.74.118',
        # key_file='~/.ssh/CertifierBiswasMarc24.pem',
    #     vm_type='client',
    #     workflow='snp_calling',
    #     workflow_args={
    #         **common_args,
    #         'reference_genome': '/root/ecoli_reference.fa',
    #         'dataset_file': '/root/example.rg.bam'
    #     }
    # )