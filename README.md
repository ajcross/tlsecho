# tlsecho

Simple https test server that returns (and logs) info about the connection: headers, protocols and a bit more

Supports http 1.0 to 3.0, tls up to 1.3 and regardless the name, it also supports non-tls http access 

## Build

build with 

```
go build ./cmd/tlsecho/
```

## Docker

docker image for amd64 and arm64 can be found at 

```
docker.io/ajcross/tlsecho:latest
```

## Usage

```
# tlsecho --help
Usage of /app/tlsecho:
  -addr string
    	service address (default ":8443")
  -cert string
    	Certificate file
  -cn string
    	cn for the automatically generated certificate (default "localhost")
  -env-re string
    	regexp to filter environment variables to output (default "^TLSECHO")
  -http3
    	enable http3
  -key string
    	Certificate key file
  -set-cookie
    	set cookie (default true)
  -tls
    	tls (default true)
  -v	verbose (default true)
  -verbose
    	verbose (default true)
```

## Enviroment variables and kubernetes

tlsecho returns (and logs) environment variables that match a regexp. This can be used in kubernetes to report the node or the pod serving the request. 

Deployment definiton example (with tls disabled):

```
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: example
  name: example
spec:
  replicas: 1
  selector:
    matchLabels:
      app: example
  template:
    metadata:
      labels:
        app: example
    spec:
      containers:
      - image: docker.io/ajcross/tlsecho
        name: tlsecho
        ports:
        - containerPort: 8080
        resources: {}
        args: ["/app/tlsecho","--addr",":8080","-tls=false","--env-re=^K_"]
        env:
          - name: K_NODE
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          - name: K_POD_NAME
            valueFrom:
              fieldRef:
                fieldPath: metadata.name
          - name: K_POD_NS
            valueFrom:
              fieldRef:
                fieldPath: metadata.namespace
          - name: K_POD_IP
            valueFrom:
              fieldRef:
                fieldPath: status.podIP
          - name: K_POD_SA
            valueFrom:
              fieldRef:
                fieldPath: spec.serviceAccountName
```

