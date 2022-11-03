
## 使用 k8s 部署

[Deploying in k8s](./README-K8S.md)

### 1. 创建 postgres-deploy.yaml 文件
`postgres-deploy.yaml` 文件内容及说明如下：
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: default
  name: postgres-wolf
  labels:
    app: postgres-wolf
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres-wolf
  template:
    metadata:
      labels:
        app: postgres-wolf
    spec:
      containers:
        - name: postgres-wolf
          image: postgres:11.4
          imagePullPolicy: Always
          ports:
            - containerPort: 5432
              name: http
              protocol: TCP
          env:
            - name: TZ
              value: Asia/Shanghai
              # 连接数据库的用户名
            - name: POSTGRES_USER
              value: root
              # 连接数据库的密码
            - name: POSTGRES_PASSWORD
              value: "R0FSCY2pcuAlWhmp"
              # 指定数据库名称，会自动创建数据库
            - name: POSTGRES_DB
              value: wolf
          resources:
            requests:
              cpu: 500m
              memory: 500Mi
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
      volumes:
        - name: data
          # 这里使用的是临时目录，容器重启后数据会丢失
          # 为了持久化数据建议挂载 pvc
          emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  namespace: default
  name: postgres-wolf
  labels:
    app: postgres-wolf
spec:
  ports:
    - name: port
      port: 5432
      protocol: TCP
      targetPort: 5432
  selector:
    app: postgres-wolf
  type: ClusterIP


```
#### 在 k8s 中部署 postgres

```shell
kubectl apply -f postgres-deploy.yaml
```
使用下面的命令查看 pod 是否正常运行
```shell
[root@node01 ~]# kubectl get pod -n default
NAME                                     READY   STATUS    RESTARTS   AGE
postgres-wolf-54d8dbfbf-9t629            1/1     Running   0          42m
```
#### 初始化数据
使用下面的命令将 [db.sql](../server/script/db.sql) 复制到容器中，`db.sql` 需要在当前目录
```shell
kubectl cp db.sql postgres-wolf-54d8dbfbf-9t629:/
```
使用下面的命令执行 db.sql 脚本
```shell
kubectl exec postgres-wolf-54d8dbfbf-9t629 -- psql  -d wolf  -f /db.sql
```
> 注意 `postgres-wolf-54d8dbfbf-9t629` 是 pod 的名字
> 
> 如果有外部的 postgres 则不需要部署上面的 postgres


### 2. 创建 wolf-rbac helm values 文件
`values.yaml` 文件内容及说明如下：
```yaml
metaAnnotations: 
  kubesphere.io/alias-name: wolf-rbac #别名
  kubesphere.io/description: apisix资源权限管理 #描述

service:
  type: NodePort #在K8s节点上暴露端口
  port: 12180 #sevice 端口
  nodePort: 30180 #容器节点端口

env: 
  - name: RBAC_ROOT_PASSWORD #root账号及admin账号的默认密码. 默认为123456
    value: "123456"    
  - name: RBAC_TOKEN_KEY # 加密用户token使用的KEY, 强烈建议设置该值
    value: "xxxxxx"
  - name: WOLF_CRYPT_KEY # 加密应用Secret及OAuth2登陆用户ID使用的Key
    value: "xxxxxx"
  - name: "RBAC_SQL_URL"
    value: "postgres://root:R0FSCY2pcuAlWhmp@postgres-wolf:5432/wolf"
  - name: CLIENT_CHANGE_PWD #设置不允许修改密码
    value: "no"
  - name: CONSOLE_TOKEN_EXPIRE_TIME #控制台token失效时长
    value: "86400"
  - name: RBAC_TOKEN_EXPIRE_TIME #RBAC token失效时长
    value: "7200"
  - name: RBAC_USERSIGN_CHECK_TIME
    value: "7200000"
  - name: OAUTH_ACCESS_TOKEN_LIFETIME
    value: "7200"
  - name: OAUTH_REFRESH_TOKEN_LIFETIME
    value: "86400"
  - name: RBAC_RECORD_ACCESS_LOG #是否启用日志记录
    value: "no"  
  - name: RECORD_LAST_LOGIN_TIME #是否记录最后登录时间，开启会损耗性能
    value: "no"
  - name: MEM_CACHE_BY_REDIS # 是否启用redis加速
    value: "yes"
  - name: RBAC_REDIS_URL #redis连接，redis://user:password@127.0.0.1:6379/1，没有用户的版本user置空
    value: "redis://:password@127.0.0.1:6379/1"
  - name: LOG_LEVEL
    value: "error" 
# 配置健康检查策略
livenessProbe:
  httpGet:
    scheme: HTTP
    path: /wolf/ping
    port: 12180
  initialDelaySeconds: 10
  timeoutSeconds: 5
  periodSeconds: 10
  successThreshold: 1
  failureThreshold: 3
readinessProbe:
  httpGet:
    scheme: HTTP
    path: /wolf/ping
    port: 12180
  initialDelaySeconds: 10
  timeoutSeconds: 5
  periodSeconds: 10
  successThreshold: 1
  failureThreshold: 3
startupProbe:
  httpGet:
    scheme: HTTP
    path: /wolf/ping
    port: 12180
  initialDelaySeconds: 10
  timeoutSeconds: 5
  periodSeconds: 10
  successThreshold: 1
  failureThreshold: 3


```
#### 2. 使[service-deploy](https://github.com/midaug/helm/tree/main/service-deploy)的helm chart在 k8s 集群中部署 wolf-server
```shell
helm upgrade wolf-server https://github.com/midaug/helm/releases/download/service-deploy-0.1.0/service-deploy-0.1.0.tgz \   
--install --create-namespace --namespace default -f ./values.yaml \   
--set image.repository=midaug/wolf-server \   
--set image.tag=v0.0.2-0.5.4 \   
--set replicaCount=2 \
--set resources.limits.cpu=1000m --set resources.limits.memory=512Mi --set resources.requests.cpu=128m --set resources.requests.memory=256Mi
```
使用下面的命令查看 pod 是否正常运行
```shell
[root@node01 ~]# kubectl get pod -n default
NAME                                     READY   STATUS    RESTARTS   AGE
postgres-wolf-54d8dbfbf-9t629            1/1     Running   0          42m
wolf-server-b8f588587-xv97t              1/1     Running   0          2m
```

#### 3. 使用账号登录控制台
访问前面暴露的服务：http://localhost:12180

![登录页面](../docs/imgs/screenshot/console/login.png)

从 [init-root-user.js](../server/src/util/init-root-user.js) 中的代码中可以看出：
```js
async function addRootUser() {
  await createUser('root', 'root(super man)', 'super')
  await createUser('admin', 'administrator', 'admin')
}
setTimeout(()=> {
    addRootUser().then(() => {

    }).catch((err) => {
        console.log('create root user failed! err: %s', err)
    })
}, 1000 * 1);
```
服务第一次启动的时候会自动创建两个用户：`root` 和 `admin`，密码为前面 `RBAC_ROOT_PASSWORD` 设置的密码。

