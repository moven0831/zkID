#!/bin/bash

usage() {
  echo "Usage: $0 {jwt|show|ecdsa|rsa2048|rsa4096|all}"
  echo "  jwt: Compile files for JWT."
  echo "  show: Compile files for Show."
  echo "  ecdsa: Compile files for ECDSA."
  echo "  rsa2048: Compile files for RSA-2048 verify."
  echo "  rsa4096: Compile files for RSA-4096 verify."
  echo "  all: Compile all circuits."
  exit 1
}

if [ -z "$1" ]; then
  echo "Error: No option provided."
  usage
fi

case "$1" in
  jwt)
    npx circomkit compile jwt || { echo "Error: Failed to compile JWT."; exit 1; }
    cd build/jwt/ || { echo "Error: 'build/jwt/' directory not found."; exit 1; }
    cp jwt.r1cs jwt_js/ || { echo "Error: Failed to copy jwt.r1cs."; exit 1; }
    cd ../.. || exit 1
    mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
    [ ! -f build/cpp/jwt.cpp ] && cp build/jwt/jwt_cpp/jwt.cpp build/cpp/ || true
    [ ! -f build/cpp/jwt.dat ] && cp build/jwt/jwt_cpp/jwt.dat build/cpp/ || true
    echo "JWT file processing complete."
    ;;
  show)
    npx circomkit compile show || { echo "Error: Failed to compile Show."; exit 1; }
    cd build/show/ || { echo "Error: 'build/show/' directory not found."; exit 1; }
    cp show.r1cs show_js/ || { echo "Error: Failed to copy show.r1cs."; exit 1; }
    cd ../.. || exit 1
    mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
    [ ! -f build/cpp/show.cpp ] && cp build/show/show_cpp/show.cpp build/cpp/ || true
    [ ! -f build/cpp/show.dat ] && cp build/show/show_cpp/show.dat build/cpp/ || true
    echo "Show file processing complete."
    ;;
  ecdsa)
    npx circomkit compile ecdsa || { echo "Error: Failed to compile ECDSA."; exit 1; }
    cd build/ecdsa/ || { echo "Error: 'build/ecdsa/' directory not found."; exit 1; }
    cp ecdsa.r1cs ecdsa_js/ || { echo "Error: Failed to copy ecdsa.r1cs."; exit 1; }
    cd ../.. || exit 1
    mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
    [ ! -f build/cpp/ecdsa.cpp ] && cp build/ecdsa/ecdsa_cpp/ecdsa.cpp build/cpp/ || true
    [ ! -f build/cpp/ecdsa.dat ] && cp build/ecdsa/ecdsa_cpp/ecdsa.dat build/cpp/ || true
    echo "ECDSA file processing complete."
    ;;
  rsa2048)
    npx circomkit compile rsa_verify_2048 || { echo "Error: Failed to compile RSA-2048."; exit 1; }
    cd build/rsa_verify_2048/ || { echo "Error: 'build/rsa_verify_2048/' directory not found."; exit 1; }
    cp rsa_verify_2048.r1cs rsa_verify_2048_js/ || { echo "Error: Failed to copy rsa_verify_2048.r1cs."; exit 1; }
    cd ../.. || exit 1
    mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
    [ ! -f build/cpp/rsa_verify_2048.cpp ] && cp build/rsa_verify_2048/rsa_verify_2048_cpp/rsa_verify_2048.cpp build/cpp/ || true
    [ ! -f build/cpp/rsa_verify_2048.dat ] && cp build/rsa_verify_2048/rsa_verify_2048_cpp/rsa_verify_2048.dat build/cpp/ || true
    echo "RSA-2048 file processing complete."
    ;;
  rsa4096)
    npx circomkit compile rsa_verify_4096 || { echo "Error: Failed to compile RSA-4096."; exit 1; }
    cd build/rsa_verify_4096/ || { echo "Error: 'build/rsa_verify_4096/' directory not found."; exit 1; }
    cp rsa_verify_4096.r1cs rsa_verify_4096_js/ || { echo "Error: Failed to copy rsa_verify_4096.r1cs."; exit 1; }
    cd ../.. || exit 1
    mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
    [ ! -f build/cpp/rsa_verify_4096.cpp ] && cp build/rsa_verify_4096/rsa_verify_4096_cpp/rsa_verify_4096.cpp build/cpp/ || true
    [ ! -f build/cpp/rsa_verify_4096.dat ] && cp build/rsa_verify_4096/rsa_verify_4096_cpp/rsa_verify_4096.dat build/cpp/ || true
    echo "RSA-4096 file processing complete."
    ;;
  all)
    echo "Compiling all circuits..."
    mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
    npx circomkit compile jwt || { echo "Error: Failed to compile JWT."; exit 1; }
    cd build/jwt/ && cp jwt.r1cs jwt_js/ && cd ../.. || { echo "Error: Failed to process JWT."; exit 1; }
    [ ! -f build/cpp/jwt.cpp ] && cp build/jwt/jwt_cpp/jwt.cpp build/cpp/ || true
    [ ! -f build/cpp/jwt.dat ] && cp build/jwt/jwt_cpp/jwt.dat build/cpp/ || true
    npx circomkit compile show || { echo "Error: Failed to compile Show."; exit 1; }
    cd build/show/ && cp show.r1cs show_js/ && cd ../.. || { echo "Error: Failed to process Show."; exit 1; }
    [ ! -f build/cpp/show.cpp ] && cp build/show/show_cpp/show.cpp build/cpp/ || true
    [ ! -f build/cpp/show.dat ] && cp build/show/show_cpp/show.dat build/cpp/ || true
    npx circomkit compile ecdsa || { echo "Error: Failed to compile ECDSA."; exit 1; }
    cd build/ecdsa/ && cp ecdsa.r1cs ecdsa_js/ && cd ../.. || { echo "Error: Failed to process ECDSA."; exit 1; }
    [ ! -f build/cpp/ecdsa.cpp ] && cp build/ecdsa/ecdsa_cpp/ecdsa.cpp build/cpp/ || true
    [ ! -f build/cpp/ecdsa.dat ] && cp build/ecdsa/ecdsa_cpp/ecdsa.dat build/cpp/ || true
    npx circomkit compile rsa_verify_2048 || { echo "Error: Failed to compile RSA-2048."; exit 1; }
    cd build/rsa_verify_2048/ && cp rsa_verify_2048.r1cs rsa_verify_2048_js/ && cd ../.. || { echo "Error: Failed to process RSA-2048."; exit 1; }
    [ ! -f build/cpp/rsa_verify_2048.cpp ] && cp build/rsa_verify_2048/rsa_verify_2048_cpp/rsa_verify_2048.cpp build/cpp/ || true
    [ ! -f build/cpp/rsa_verify_2048.dat ] && cp build/rsa_verify_2048/rsa_verify_2048_cpp/rsa_verify_2048.dat build/cpp/ || true
    npx circomkit compile rsa_verify_4096 || { echo "Error: Failed to compile RSA-4096."; exit 1; }
    cd build/rsa_verify_4096/ && cp rsa_verify_4096.r1cs rsa_verify_4096_js/ && cd ../.. || { echo "Error: Failed to process RSA-4096."; exit 1; }
    [ ! -f build/cpp/rsa_verify_4096.cpp ] && cp build/rsa_verify_4096/rsa_verify_4096_cpp/rsa_verify_4096.cpp build/cpp/ || true
    [ ! -f build/cpp/rsa_verify_4096.dat ] && cp build/rsa_verify_4096/rsa_verify_4096_cpp/rsa_verify_4096.dat build/cpp/ || true
    echo "All circuits compiled successfully."
    ;;
  *)
    echo "Error: Invalid option '$1'."
    usage
    ;;
esac

