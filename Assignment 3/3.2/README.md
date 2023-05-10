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
Then the app will be launched in `http://145.100.135.195:30001/`

Stop the work pods to run below
```
kubectl scale deployment flask-app --replicas=0
```