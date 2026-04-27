sudo docker run -d \
  --name rev_aes_demo \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,size=200m \
  --tmpfs /home/ctfplayer:rw,size=500m \
  --volume "/home/ubuntu/codes/crypto-code/CREBench/C-openssl/aes_demo_low":/work/aes_demo_static_min:ro \
  --workdir /work \
  rev-sandbox:latest \
  sleep infinity


sudo docker build -t rev-sandbox:latest -f Dockerfile . --net=host

sudo docker buildx build --platform=linux/amd64 -t rev-sandbox:latest .

sudo docker build \
  --build-arg HTTP_PROXY=http://192.168.31.22:7890 \
  --build-arg HTTPS_PROXY=http://192.168.31.22:7890 \
  -t rev-sandbox:latest . --platform=linux/amd64 


  
