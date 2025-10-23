import paramiko
from time import sleep
from pathlib import Path
import os.path
import sys
import argparse

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
    print("[DEBUG] Starting Docker installation process using convenience script")

    # Check if Docker is already installed with a different package
    print("[DEBUG] Checking if Docker is already installed via other packages")
    stdin, stdout, stderr = ssh.exec_command("which docker", get_pty=True)
    if stdout.read().decode().strip():
        print("[DEBUG] Docker binary already exists, proceeding with existing installation")
        return True

    # Step 1: Update system
    print("[DEBUG] Updating system packages")
    stdin, stdout, stderr = ssh.exec_command("sudo apt-get update", get_pty=True)
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        print(f"[ERROR] System update failed with exit status {exit_status}")
        return False

    # Step 2: Install prerequisites
    print("[DEBUG] Installing prerequisites")
    stdin, stdout, stderr = ssh.exec_command(
        "sudo apt-get install -y curl apt-transport-https ca-certificates software-properties-common", 
        get_pty=True
    )

    # Print real-time output
    while not stdout.channel.exit_status_ready():
        if stdout.channel.recv_ready():
            print(stdout.channel.recv(1024).decode(), end="")
        sleep(0.1)

    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        print(f"[ERROR] Installing prerequisites failed with exit status {exit_status}")
        return False

    # Step 3: Download and run Docker convenience script
    print("[DEBUG] Downloading Docker convenience script")
    stdin, stdout, stderr = ssh.exec_command("curl -fsSL https://get.docker.com -o get-docker.sh", get_pty=True)
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        print(f"[ERROR] Downloading Docker script failed with exit status {exit_status}")
        return False

    print("[DEBUG] Running Docker installation script")
    stdin, stdout, stderr = ssh.exec_command("sudo sh get-docker.sh", get_pty=True)

    # Print real-time output
    while not stdout.channel.exit_status_ready():
        if stdout.channel.recv_ready():
            print(stdout.channel.recv(1024).decode(), end="")
        sleep(0.1)

    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        print(f"[ERROR] Docker installation script failed with exit status {exit_status}")
        return False

    # Step 4: Add user to docker group if installation succeeded
    print("[DEBUG] Adding user to docker group")
    stdin, stdout, stderr = ssh.exec_command("sudo usermod -aG docker $USER", get_pty=True)
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        print(f"[WARNING] Adding user to docker group failed with exit status {exit_status}")
        print("[WARNING] You may need to run docker commands with sudo")

    # Step 5: Verify Docker installation
    print("[DEBUG] Verifying Docker installation")
    stdin, stdout, stderr = ssh.exec_command("sudo docker --version", get_pty=True)
    docker_version = stdout.read().decode().strip()
    exit_status = stdout.channel.recv_exit_status()

    if exit_status == 0 and docker_version:
        print(f"[DEBUG] Docker installation verified: {docker_version}")
        return True
    else:
        print("[ERROR] Docker installation verification failed")
        return False

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
            print(stdout.channel.recv(1024).decode(errors='ignore'), end="")
            
        # Print stderr
        while stderr.channel.recv_stderr_ready():
            line = stderr.channel.recv_stderr(1024).decode(errors='ignore')
            print(line, end="", flush=True)
            print(line, end="", file=sys.stderr, flush=True)
        
        sleep(0.1)
    
    exit_status = stdout.channel.recv_exit_status()
    print(f"\n=== Command completed with exit status {exit_status} ===")
    return exit_status


def build_docker_client(workflow, args):
    base_cmd =   (
    f"(docker ps -a --format '{{{{.Names}}}}' | grep -w 've3c-image' && docker rm -f ve3c-image || echo 'No container to remove') && "
    f"docker run -it --rm --name ve3c-client "
    f"bwbgv/ve3c-image client "
    f"--policy_host={args['policy_host']} "
    f"--server_app_host={args['server_app_host']} "
    f"--analysis_type={workflow}"
)
    
    if workflow == "sequence_quality":
        print(args['parameters'], "========")
        return (
            f"{base_cmd} "
            f"--dataset_file={args['dataset_file']} "
            f"--parameters=--{args['parameters']} "
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

def build_docker_client_non_high_security(workflow, args):
    result_dir = '/tmp/bio_fasta/results/'
    base_cmd = (
        f"(docker ps -a --format '{{{{.Names}}}}' | grep -w 've3c-low-client' && docker rm -f ve3c-low-client || echo 'No container to remove') && "
        f"docker run --rm --name ve3c-low-client bwbgv/ve3c-low "
    )

    
    if workflow == "sequence_quality":
        abs_input = os.path.abspath(args['dataset_file']) if args.get('dataset_file') else None
        if abs_input:
            base_name = os.path.basename(abs_input)  # Get filename with extension
            dot_pos = base_name.rfind('.')
            if dot_pos != -1:
                base_name = base_name[:dot_pos]  # Remove file extension
        return (
            f"{base_cmd} "
            f"sh -c \"mkdir -p /tmp/bio_fasta/results/ && "
            f"touch /tmp/bio_fasta/results/{base_name}_fastqc.html && "
            f"fastqc {abs_input} --threads {args.get('threads', 2)} --{args['parameters']} -o /tmp/bio_fasta/results/ 2>&1 \""
        )
    elif workflow == "read_alignment":
        abs_ref = os.path.abspath(args['reference_genome'])
        abs_paired1 = os.path.abspath(args['paired_file_1'])
        abs_paired2 = os.path.abspath(args['paired_file_2'])
        abs_ref = os.path.abspath(args['reference_genome']) if args.get('reference_genome') else None
        if abs_ref:
            base_name = os.path.basename(abs_ref)  # Get filename with extension
            dot_pos = base_name.rfind('.')
            if dot_pos != -1:
                base_name = base_name[:dot_pos]  # Remove file extension

        # Output paths
        output_bam = os.path.join('/tmp/bio_fasta/results', f"example.sorted.bam")
        final_bam = os.path.join('/tmp/bio_fasta/results', f"example.rg.bam")
        return (
            f"{base_cmd}"
            f"sh -c \"mkdir -p /tmp/bio_fasta/results/ && "
            f"touch /tmp/bio_fasta/results/example.sam && "
            f"bwa index {abs_ref} && "
            f"bwa mem -t {args['threads']} {abs_ref} {abs_paired1} {abs_paired2} > {os.path.join('/tmp/bio_fasta/results', 'example')}.sam && "
            f"samtools view -bS {os.path.join('/tmp/bio_fasta/results', 'example')}.sam | "
            f"samtools sort -o {output_bam} && "
            f"samtools index {output_bam} && "
            f"picard AddOrReplaceReadGroups "
            f"I={output_bam} "
            f"O={final_bam} "
            f"RGID=dummyID RGLB=dummyLibrary RGPL=illumina "
            f"RGPU=dummyPlatformUnit RGSM=dummySample && "
            f"samtools index {final_bam} 2>&1\""
        )
    elif workflow == "indel_calling":
        abs_ref = os.path.abspath(args['reference_genome'])
        abs_input = os.path.abspath(args['dataset_file'])
        threads = args['threads']
        if abs_input:
            base_name = os.path.basename(abs_input)  # Get filename with extension
            dot_pos = base_name.rfind('.')
            if dot_pos != -1:
                base_name = base_name[:dot_pos]  # Remove file extension
        print(abs_ref[:abs_ref.rfind('.')].strip())
        return (
            f"{base_cmd} "
            f"sh -c \"ln -s /usr/bin/python3 /usr/bin/python && "
            f"mkdir -p /tmp/bio_fasta/results/ && "
            f"samtools faidx {abs_ref} && "
            f"gatk CreateSequenceDictionary -R {abs_ref} "
            f"-O {abs_ref[:abs_ref.rfind('.')]}".strip() + ".dict && "
            f"samtools index {abs_input}  &&"
            f"gatk --java-options \"-Xmx{threads*1024}M\" HaplotypeCaller "
            f"-R {abs_ref} "
            f"-I {abs_input} "
            f"-O /tmp/bio_fasta/results/{base_name}_raw_variants.vcf && "
            f"gatk VariantFiltration -R {abs_ref} "
            f"-V /tmp/bio_fasta/results/{base_name}_raw_variants.vcf "
            f"-O /tmp/bio_fasta/results/{base_name}_filtered_indels.vcf "
            f"--filter-expression 'QD < 2.0 || FS > 200.0' "
            f"--filter-name INDEL_filter 2>&1\""
        )
    elif workflow == "snp_calling":
        abs_ref = os.path.abspath(args['reference_genome'])
        abs_input = os.path.abspath(args['dataset_file'])
        threads = args['threads']
        if abs_input:
            base_name = os.path.basename(abs_input)  # Get filename with extension
            dot_pos = base_name.rfind('.')
            if dot_pos != -1:
                base_name = base_name[:dot_pos]  # Remove file extension
        print(abs_ref[:abs_ref.rfind('.')].strip())
        return (
            f"{base_cmd} "
            f"sh -c \"ln -s /usr/bin/python3 /usr/bin/python && "
            f"mkdir -p /tmp/bio_fasta/results/ && "
            f"samtools faidx {abs_ref} && "
            f"gatk CreateSequenceDictionary -R {abs_ref} "
            f"-O {abs_ref[:abs_ref.rfind('.')]}".strip() + ".dict && "
            f"samtools index {abs_input}  &&"
            f"gatk --java-options \"-Xmx{threads*1024}M\" HaplotypeCaller "
            f"-R {abs_ref} "
            f"-I {abs_input} "
            f"-O /tmp/bio_fasta/results/{base_name}_raw_variants.vcf && "
            f"gatk VariantFiltration -R {abs_ref} "
            f"-V /tmp/bio_fasta/results/{base_name}_raw_variants.vcf "
            f"-O /tmp/bio_fasta/results/{base_name}_filtered_indels.vcf "
            f"--filter-expression 'QD < 2.0 || FS > 60.0 || MQ < 40.0' "
            f"--filter-name SNP_filter 2>&1\""
        )
    else:
        raise ValueError(f"Unknown workflow: {workflow}")

def pull_docker_image_with_retries(ssh, image_name, retries=3, delay=5):
    for attempt in range(1, retries + 1):
        print(f"\nAttempt {attempt}: Pulling Docker image {image_name}")
        exit_code = stream_command_output(ssh, f"docker pull {image_name}")
        if exit_code == 0:
            print("✅ Image pulled successfully")
            return True
        else:
            print(f"⚠️ Pull failed. Retrying in {delay} seconds...")
            sleep(delay)
    print("❌ Failed to pull Docker image after multiple attempts.")
    return False

def run_certifier_vm(client, vm_type, workflow=None, cpu=2, mem_gb=4, security_type="high", workflow_args=None):
    # ssh = paramiko.SSHClient()
    # ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # resolved_key_path = get_ssh_key_path(key_file)
    
    # print(f"Connecting to {ip} using key: {resolved_key_path}")
    # ssh.connect(ip, username=username, key_filename=resolved_key_path)
    
    try:
        #ssh.connect(ip, username=username, key_filename=key_file)
        
        # 1. Check/Install Docker
        print("\n=== Checking Docker Installation ===")
        stdin, stdout, stderr = client.exec_command('docker --version', get_pty=True)
        docker_version = stdout.read().decode().strip()
        
        if not docker_version.startswith('Docker version'):
            print("Docker not found, installing...")
            install_docker(client)
        else:
            print(f"Docker already installed: {docker_version}")
        
        # # 2. Clean up and pull image
        image_name = "bwbgv/ve3c-image:latest" if security_type.lower() == 'high' else "bwbgv/ve3c-low:latest"
        print(f"\n=== Checking for existing Docker image: {image_name} ===")
        
        if check_docker_image_exists(client, image_name):
            print("Image already exists locally, skipping pull")
        else:
            print("Image not found locally, pulling...")
            pull_docker_image_with_retries(client, image_name)
        
        # 3. Run appropriate service
        if vm_type.lower() == 'server':
            print("\n=== Starting Server ===")
            # Clean up any existing server
            stream_command_output(client, "docker rm -f ve3c-server || true")
            
            cmd = (
                f"docker network create --driver bridge certifier-net || true && "
                f"docker run -d --name ve3c-server --network certifier-net "
                f"--cpus={cpu} --memory={mem_gb}g "
                f"-p 8123:8123 -p 8124:8124 "
                f"bwbgv/ve3c-image server "
                f"--host=0.0.0.0 --policy_host=0.0.0.0 --server_app_host=0.0.0.0"
            )
            stream_command_output(client, cmd)
            
            # Monitor server logs
            print("\n=== Server Logs (Ctrl+C to stop monitoring) ===")
            try:
                stdin, stdout, stderr = client.exec_command("docker logs -f ve3c-server", get_pty=True)
                while True:
                    print(stdout.readline(), end="")
            except KeyboardInterrupt:
                print("\nStopped monitoring server logs")
                
        elif vm_type.lower() == 'client':
            if not workflow:
                raise ValueError("Workflow must be specified for client VM")
                
            print(f"\n=== Starting Client ({workflow} workflow) ===")
            print(workflow_args)
            if security_type.lower() == "high":
                cmd = build_docker_client(workflow, workflow_args)
                print(f"\n=== Starting Client with HIGH security: Running bioinformatics workflow ({workflow}) ===")
                container_name = 've3c-client'
            else:
                print(f"\n=== Starting Client with {security_type.upper()} security: Running alternative container workflow ===")
                container_name = 've3c-low-client'
                cmd = build_docker_client_non_high_security(workflow, workflow_args)
            print(workflow_args)
            exit_code = stream_command_output(client, cmd)     
 
            if exit_code != 0:
                print(f"\n⚠️ Client workflow failed with exit code {exit_code}")
            else:
                print(f"\n✅ Client workflow completed successfully")
            print("\n=== Cleaning up Docker container ===")
            stream_command_output(client, "docker rm -f ve3c-low-client || true")
                
        else:
            raise ValueError("vm_type must be either 'server' or 'client'")
            
    except Exception as e:
        print(e)
        #print(f"\n❌ Error on {ip}: {str(e)}")
    finally:
        # ssh.close()
        print("\n=== SSH Connection Closed for this workflow execution ===")

# def run_certifier_vm(ip, username, key_file, vm_type, workflow=None, cpu=2, mem_gb=4, security_type="high", workflow_args=None):
#     ssh = paramiko.SSHClient()
#     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     resolved_key_path = get_ssh_key_path(key_file)
    
#     print(f"Connecting to {ip} using key: {resolved_key_path}")
#     ssh.connect(ip, username=username, key_filename=resolved_key_path)
    
#     try:
#         ssh.connect(ip, username=username, key_filename=key_file)
        
#         # 1. Check/Install Docker
#         print("\n=== Checking Docker Installation ===")
#         stdin, stdout, stderr = ssh.exec_command('docker --version', get_pty=True)
#         docker_version = stdout.read().decode().strip()
        
#         if not docker_version.startswith('Docker version'):
#             print("Docker not found, installing...")
#             install_docker(ssh)
#         else:
#             print(f"Docker already installed: {docker_version}")
        
#         # # 2. Clean up and pull image
#         image_name = "bwbgv/ve3c-image:latest" if security_type.lower() == 'high' else "bwbgv/ve3c-low:latest"
#         print(f"\n=== Checking for existing Docker image: {image_name} ===")
        
#         if check_docker_image_exists(ssh, image_name):
#             print("Image already exists locally, skipping pull")
#         else:
#             print("Image not found locally, pulling...")
#             pull_docker_image_with_retries(ssh, image_name)
        
#         # 3. Run appropriate service
#         if vm_type.lower() == 'server':
#             print("\n=== Starting Server ===")
#             # Clean up any existing server
#             stream_command_output(ssh, "docker rm -f ve3c-server || true")
            
#             cmd = (
#                 f"docker network create --driver bridge certifier-net || true && "
#                 f"docker run -d --name ve3c-server --network certifier-net "
#                 f"--cpus={cpu} --memory={mem_gb}g "
#                 f"-p 8123:8123 -p 8124:8124 "
#                 f"bwbgv/ve3c-image server "
#                 f"--host=0.0.0.0 --policy_host=0.0.0.0 --server_app_host=0.0.0.0"
#             )
#             stream_command_output(ssh, cmd)
            
#             # Monitor server logs
#             print("\n=== Server Logs (Ctrl+C to stop monitoring) ===")
#             try:
#                 stdin, stdout, stderr = ssh.exec_command("docker logs -f ve3c-server", get_pty=True)
#                 while True:
#                     print(stdout.readline(), end="")
#             except KeyboardInterrupt:
#                 print("\nStopped monitoring server logs")
                
#         elif vm_type.lower() == 'client':
#             if not workflow:
#                 raise ValueError("Workflow must be specified for client VM")
                
#             print(f"\n=== Starting Client ({workflow} workflow) ===")
#             print(workflow_args)
#             if security_type.lower() == "high":
#                 cmd = build_docker_client(workflow, workflow_args)
#                 print(f"\n=== Starting Client with HIGH security: Running bioinformatics workflow ({workflow}) ===")
#                 container_name = 've3c-client'
#             else:
#                 print(f"\n=== Starting Client with {security_type.upper()} security: Running alternative container workflow ===")
#                 container_name = 've3c-low-client'
#                 cmd = build_docker_client_non_high_security(workflow, workflow_args)
#             print(workflow_args)
#             exit_code = stream_command_output(ssh, cmd)     

#             if exit_code != 0:
#                 print(f"\n⚠️ Client workflow failed with exit code {exit_code}")
#             else:
#                 print(f"\n✅ Client workflow completed successfully")
#             print("\n=== Cleaning up Docker container ===")
#             stream_command_output(ssh, "docker rm -f ve3c-low-client || true")
                
#         else:
#             raise ValueError("vm_type must be either 'server' or 'client'")
            
#     except Exception as e:
#         print(e)
#         print(f"\n❌ Error on {ip}: {str(e)}")
#     finally:
#         # ssh.close()
#         print("\n=== SSH Connection Closed ===")

    
def main():
    parser = argparse.ArgumentParser(description="Control certifier pipeline VMs")
    parser.add_argument('--key_file', required=True, help='Path to SSH private key')
    parser.add_argument('--ip', required=True, help='VM IP address')
    parser.add_argument('--username', required=True, help='VM Username address')
    parser.add_argument('--vm_type', required=True, choices=['server', 'client'], help='Type of VM to control')
    parser.add_argument('--security_type', required=True, choices=['medium', 'high', 'low'], help='Type of security you desire')

    
    # Common optional arguments
    parser.add_argument('--cpus', type=int, default=2, help='CPU cores to allocate (default: 2)')
    parser.add_argument('--mem', type=int, default=4, help='Memory in GB (default: 4)')
    
    # Client-specific arguments
    parser.add_argument('--workflow', choices=['sequence_quality', 'read_alignment', 'indel_calling', 'snp_calling'], 
                      help='Workflow type (required for client)')
    parser.add_argument('--policy_host', default='0.0.0.0', help='Policy server host (required for client)')
    parser.add_argument('--server_app_host', default='0.0.0.0', help='Policy server host to run server application')


    
    parser.add_argument('--dataset_file', help='Input dataset file path')
    parser.add_argument('--reference_genome', help='Reference genome file path')
    parser.add_argument('--paired_file_1', help='First paired-end file')
    parser.add_argument('--paired_file_2', help='Second paired-end file')
    parser.add_argument('--parameters', help='Workflow parameters')
    parser.add_argument('--threads', type=int, default=2, help='Number of threads (default: 2)')
    
    args = parser.parse_args()
    
    # Validate client-specific requirements
    if args.vm_type == 'client':
        if not args.workflow:
            parser.error("--workflow is required for client VMs")

        
        workflow_args = {
            'policy_host': args.policy_host,
            'server_app_host': args.server_app_host,  # Using same host for both
            'dataset_file': args.dataset_file,
            'reference_genome': args.reference_genome,
            'paired_file_1': args.paired_file_1,
            'paired_file_2': args.paired_file_2,
            'threads': args.threads,
            'parameters': args.parameters
        }
        
        # Clean up None values
        workflow_args = {k: v for k, v in workflow_args.items() if v is not None}
    else:
        workflow_args = {}
    
    # common_args = {
    #     'policy_host': '172.31.20.155',
    #     'server_app_host': '172.31.20.155'
    # }
    
    # Call the main function
    run_certifier_vm(
        ip=args.ip,
        username=args.username,
        key_file=args.key_file,
        vm_type=args.vm_type,
        workflow=args.workflow,
        cpu=args.cpus,
        mem_gb=args.mem,
        security_type=args.security_type,
        workflow_args={
         **workflow_args 
        }
    )

if __name__ == '__main__':
    main()



# # Example usage for different workflows
# if __name__ == "__main__":
#     common_args = {
#         'policy_host': '172.31.20.155',
#         'server_app_host': '172.31.20.155'
#     }
    
#     # 1. Start server
#     run_certifier_vm(
#         ip='98.81.94.29',
#         key_file='/Users/bishwaswagle/.ssh/CertifierBiswasMarc24.pem',
#         vm_type='server'
#     )
    
# #     # 2. Run FastQC client
    # run_certifier_vm(
    #     ip='34.227.74.118',
    #     key_file='/Users/bishwaswagle/.ssh/CertifierBiswasMarc24.pem',
    #     vm_type='client',
    #     workflow='sequence_quality',
    #     security_type="low",
    #     workflow_args={
    #         **common_args,
    #         'dataset_file': '/root/SRR2584863_1_1.fastq',
    #         'parameters': 'quiet',
    #         'threads': 2,
    #     }
    # )
    
#     # 3. Run Read Alignment client
    # run_certifier_vm(
    #     ip='34.227.74.118',
    #     key_file='/Users/bishwaswagle/.ssh/CertifierBiswasMarc24.pem',
    #     vm_type='client',
    #     workflow='read_alignment',
    #     workflow_args={
    #         **common_args,
    #         'reference_genome': '/root/ecoli_reference.fa',
    #         'paired_file_1': '/root/SRR2584863_1.fastq',
    #         'paired_file_2': '/root/SRR2584863_2.fastq'
    #     }
    # )
    
#     # # 4. Run Indel Calling client
    # run_certifier_vm(
    #     ip='34.227.74.118',
    #     key_file='/Users/bishwaswagle/.ssh/CertifierBiswasMarc24.pem',
    #     vm_type='client',
    #     workflow='indel_calling',
    #     workflow_args={
    #         **common_args,
    #         'reference_genome': '/root/ecoli_reference.fa',
    #         'dataset_file': '/root/example.rg.bam'
    #     }
    # )

#     # # 5. Run SNP Calling client
#     # run_certifier_vm(
#     #     ip='34.227.74.118',
#     #     key_file='/Users/bishwaswagle/.ssh/CertifierBiswasMarc24.pem',
#     #     vm_type='client',
#     #     workflow='snp_calling',
#     #     workflow_args={
#     #         **common_args,
#     #         'reference_genome': '/root/ecoli_reference.fa',
#     #         'dataset_file': '/root/example.rg.bam'
#     #     }
#     # )



# bwa index ecoli_reference.fa && bwa  mem -t 8 ecoli_reference.fa SRR2584863_0.1_1.fastq SRR2584863_0.1_2.fastq > ./ra/results.sam && samtools view -bS ./ra/results.sam | samtools sort -o ./ra/results.sorted.bam && samtools index ./ra/results.sorted.bam && java -jar picard.jar AddOrReplaceReadGroups I=./ra/results.sorted.bam O=./ra/results.rg.bam RGID=dummyID RGLB=dummyLibrary RGPL=illumina RGPU=dummyPlatformUnit RGSM=dummySample && samtools index ./ra/results.rg.bam 2>&1


