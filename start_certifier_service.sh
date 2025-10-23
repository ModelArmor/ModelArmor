#!/bin/bash

set -e  # Exit on error
set -o pipefail

# Set up environment variables
export CERTIFIER_PROTOTYPE=/root/certifier-framework-for-confidential-computing
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app

export PATH=$PATH:/usr/local/go/bin 
export PATH=$PATH:$(go env GOPATH)/bin

echo "[*] Cleaning up non-Git files..."
cd $CERTIFIER_PROTOTYPE/sample_apps
./run_example.sh simple_app rm_non_git_files
cd $EXAMPLE_DIR
rm -rf app1_data/ app2_data/

echo "[*] Building certifier utilities..."
cd $CERTIFIER_PROTOTYPE/utilities
make -f cert_utility.mak
make -f policy_utilities.mak

echo "[*] Creating provisioning directory..."
rm -rf $EXAMPLE_DIR/provisioning
mkdir $EXAMPLE_DIR/provisioning

echo "[*] Generating policy and platform keys..."
cd $EXAMPLE_DIR/provisioning
$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe --operation=generate-policy-key-and-test-keys \
    --policy_key_output_file=policy_key_file.bin \
    --policy_cert_output_file=policy_cert_file.bin \
    --platform_key_output_file=platform_key_file.bin \
    --attest_key_output_file=attest_key_file.bin

echo "[*] Embedding policy key..."
$CERTIFIER_PROTOTYPE/utilities/embed_policy_key.exe \
    --input=policy_cert_file.bin \
    --output=../policy_key.cc

echo "[*] Compiling example app..."
cd $EXAMPLE_DIR
make -f example_app.mak

echo "[*] Obtaining trusted app measurement..."
cd $EXAMPLE_DIR/provisioning
$CERTIFIER_PROTOTYPE/utilities/measurement_utility.exe \
    --type=hash --input=../example_app.exe --output=example_app.measurement

echo "[*] Constructing trust statements..."
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe \
    --key_subject=platform_key_file.bin \
    --verb="is-trusted-for-attestation" \
    --output=ts1.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe \
    --key_subject=policy_key_file.bin \
    --verb="says" --clause=ts1.bin \
    --output=vse_policy1.bin

$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe \
    --measurement_subject=example_app.measurement \
    --verb="is-trusted" --output=ts2.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe \
    --key_subject=policy_key_file.bin \
    --verb="says" --clause=ts2.bin \
    --output=vse_policy2.bin

echo "[*] Signing trust claims..."
$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe \
    --vse_file=vse_policy1.bin --duration=9000 \
    --private_key_file=policy_key_file.bin --output=signed_claim_1.bin

$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe \
    --vse_file=vse_policy2.bin --duration=9000 \
    --private_key_file=policy_key_file.bin --output=signed_claim_2.bin

$CERTIFIER_PROTOTYPE/utilities/package_claims.exe \
    --input=signed_claim_1.bin,signed_claim_2.bin \
    --output=policy.bin

echo "[*] Signing attestation endorsement..."
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe \
    --key_subject=attest_key_file.bin \
    --verb="is-trusted-for-attestation" --output=tsc1.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe \
    --key_subject=platform_key_file.bin --verb="says" \
    --clause=tsc1.bin --output=vse_policy3.bin

$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe \
    --vse_file=vse_policy3.bin --duration=9000 \
    --private_key_file=platform_key_file.bin \
    --output=platform_attest_endorsement.bin

echo "[*] Building Certifier Service..."
cd $CERTIFIER_PROTOTYPE/certifier_service/certprotos
protoc --go_opt=paths=source_relative --go_out=. --go_opt=M=certifier.proto ./certifier.proto

cd $CERTIFIER_PROTOTYPE/certifier_service/oelib
make dummy

cd $CERTIFIER_PROTOTYPE/certifier_service/teelib
make

cd $CERTIFIER_PROTOTYPE/certifier_service/graminelib
make dummy

cd $CERTIFIER_PROTOTYPE/certifier_service/isletlib
make dummy

cd $CERTIFIER_PROTOTYPE/certifier_service
go build simpleserver.go

echo "[*] Setting up data directories..."
cd $EXAMPLE_DIR
mkdir -p service app1_data app2_data app3_data

echo "[*] Provisioning app and service files..."
cp -p provisioning/* app1_data/
cp -p provisioning/* app2_data/
cp -p provisioning/* app3_data/
cp -p provisioning/policy_key_file.bin provisioning/policy_cert_file.bin provisioning/policy.bin service/


