# porecry - post-renderer-crypt

With Helm >= v3.1.1 there is the possibillity to run a post renderer after the templates has been renderered by helm. porecry is a post-renderer which can be used to decrypt values which are stored encrypted in the values.yaml files which are used to renderer the helm templates.

## Idea

The goal is to be able to store the secrets `values.yaml` in the repository encrypted. When using helm to render the manifests, the post-renderer can decrypt the values used in the secrets manifests.  

## Workflow

* create a porecry secret (local or in cluster)
* use porecry to get the base64 ciphertext
* store the ciphertext in the values.yaml for the helm chart
* use porecry as post-renderer along with helm 

## Install

You can download the binary from the release page and install it in your $PATH

### build yourself

To build the tool your self you need `make`, `git` and `go`

```bash
git clone https://github.com/sebidude/porecry.git
cd porecry
make build-linux
```

## Create a porecry secret

A porecry secrets is a simple kubernetes secret which can be stored locally or in the clusters. 

Create a porecry secret

```bash
porecry init --secret porecry --namespace mynamespace -o secret.yaml
```

You can now add the secret to your cluster.

```bash
kubectl apply -f secret.yaml
```

## Create the ciphertext for you values

If the secret is not added to the cluster you can use the following flags to use it from the local file created previously.

```bash
export PORECRY_LOCAL="--local --secret secret.yaml"
```

Now let's encrypt some data.
```bash
echo -n "mypassword" | porecry $PORECRY_LOCAL enc
```

## store the ciphertext in the values.yaml

```yaml
myapp:
  lables:
    app: myapp
  service:
    port: 8080
  secrets:
    password: "[op:decrypt,mode:local,secret:secret.yaml] --- here goes the ciphertext ---"
```

Note the meta information stated in front of the ciphertext. This tells porecry how to process the following data. 

* `op` - operation. 
  * `encrypt` - encrypt the value 
  * `decrypt` - decrypt the value
* `mode`
  * `local` - use the secret from a local file which contains the secret manifest
  * `cluster` - load the secret from the cluster, your kubeconfig is pointing to
* `secret`
  * `filename` can be specified when `mode` is `local`
  * `namespace/secretname` can be specified when `mode` is `cluster`

Example:

```
[op:encrypt,mode:local,secret:secret.yaml]this is plaintext`  
```

encrypt the value `this is plaintext` using the secret from the `local` file `secret.yaml`

```
[op:encrypt,mode:cluster,secret:kube-system/porecry]this is plaintext
``` 

encrypt the value `this is plaintext` using the secret `porecry` found in namespace `kube-system` in the cluster your kubeconfig points to.

## Decrypt the file

```
cat values.yaml | porecry $PORECRY_LOCAL post
```

## Use in charts

In a helm chart one would create a template for the applications secrets and render the values from the values.yaml into it and then use the `--post-renderer porecry` to decrypt the values in the rendered manifests.

First copy your values.yaml which we created previously to the `examples/porecry` folder in your checkout.

```
helm template porecry examples/porecry --post-renderer porecry
```



