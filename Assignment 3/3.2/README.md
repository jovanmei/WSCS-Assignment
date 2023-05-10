## Assignment 3.2
Build the docker image
```
docker build --no-cache -t jovanmei/app:v1 .
```
Then run to push it to the hub
```
docker push jovanmei/app:v1
```
Apply the configuration file
```
kubectl apply -f /opt/deployment.yaml
kubectl apply -f /opt/services.yaml
```
Stop the work pods
```
kubectl scale deployment flask-app --replicas=0
```