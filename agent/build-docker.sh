#!/bin/bash
# Build script for KratosComply Agent Docker image
# Run this script from the agent/ directory

set -e

IMAGE_NAME="${IMAGE_NAME:-popslala1/kratos-agent}"
VERSION="${VERSION:-latest}"
DOCKERFILE="${DOCKERFILE:-Dockerfile}"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Building Docker image: ${IMAGE_NAME}:${VERSION}"
echo "Using Dockerfile: ${SCRIPT_DIR}/${DOCKERFILE}"
echo "Build context: ${PROJECT_ROOT}"

# Build the image from project root with agent Dockerfile
cd "${PROJECT_ROOT}"
docker build -t "${IMAGE_NAME}:${VERSION}" -f "${SCRIPT_DIR}/${DOCKERFILE}" .

# Also tag as latest if version is not latest
if [ "${VERSION}" != "latest" ]; then
    docker tag "${IMAGE_NAME}:${VERSION}" "${IMAGE_NAME}:latest"
    echo "Tagged as ${IMAGE_NAME}:latest"
fi

echo ""
echo "Build complete!"
echo ""
echo "To test the image:"
echo "  docker run --rm ${IMAGE_NAME}:${VERSION} --help"
echo ""
echo "To push to Docker Hub:"
echo "  docker login"
echo "  docker push ${IMAGE_NAME}:${VERSION}"
if [ "${VERSION}" != "latest" ]; then
    echo "  docker push ${IMAGE_NAME}:latest"
fi

