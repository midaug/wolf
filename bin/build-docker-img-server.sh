if [ "$#" == "0" ]; then
  echo "Usage: sh $0 TAG"
  echo "\tTAG: 1.2.3"
  exit 1
fi

TAG="$1"
echo "BUILD TAG: $TAG"
echo "BUILD CONSOLE..."
cd ./console && npm install && npm run build:prod
if [ "$?" != "0" ]; then
  echo "build console failed!"
  exit 2
fi
cd ../
echo "BUILD SERVER..."
docker build -t midaug/wolf-server:$TAG -f ./server/Dockerfile ./server
docker build -t midaug/wolf-server:latest -f ./server/Dockerfile ./server
echo "BUILD SUCCESS."