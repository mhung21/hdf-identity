# Skill: Build & Deploy Docker — HDF Identity

Skill này dùng để build Docker image cho `hdf-identity`, push lên Docker Hub, và update stack trên Portainer.

## Yêu cầu

- **Hỏi người dùng** chọn môi trường: `prod` hoặc `dev`
- Nếu không chỉ rõ, **PHẢI hỏi lại** trước khi thực hiện

## Thông tin

| Key | Value |
|---|---|
| Docker Hub User | `xuantruong2204` |
| Portainer URL | `https://103.176.179.103:9443` |
| Portainer User | `admin` |
| Portainer Password | `&67$g*a$c7Z@zd8M` |
| Source code | `d:\SourceCode\Hdf\hdf-identity\hdf-identity\CrediFlow.Identity` |
| Dockerfile | `d:\SourceCode\Hdf\hdf-identity\hdf-identity\CrediFlow.Identity\Dockerfile` |

## Cấu hình theo môi trường

| | **Production (prod)** | **Dev/Test (dev)** |
|---|---|---|
| Image tag | `xuantruong2204/crediflow-identity:prod` | `xuantruong2204/crediflow-identity:dev` |
| Portainer Stack ID | `3` (hdf-identity) | `9` (hdf-dev) |
| Container name | `hdf-identity` | `hdf-identity-test` |
| Port | `8882` | `8884` |
| Network | `hdf-net` | `hdf-test-net` |

## Các bước thực hiện

### Bước 1: Build Docker image

```bash
cd d:\SourceCode\Hdf\hdf-identity\hdf-identity\CrediFlow.Identity

# Dev
docker build -t xuantruong2204/crediflow-identity:dev .

# Prod
docker build -t xuantruong2204/crediflow-identity:prod .
```

### Bước 2: Push lên Docker Hub

```bash
# Dev
docker push xuantruong2204/crediflow-identity:dev

# Prod
docker push xuantruong2204/crediflow-identity:prod
```

### Bước 3: Update stack trên Portainer (via API)

```powershell
# Authenticate
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$authBody = '{"username":"admin","password":"&67$g*a$c7Z@zd8M"}'
$token = (Invoke-RestMethod -Uri 'https://103.176.179.103:9443/api/auth' -Method Post -Body $authBody -ContentType 'application/json').jwt
$headers = @{Authorization="Bearer $token"}

# Dev (Stack ID 9 — hdf-dev, chứa cả DB + Identity + API):
$compose = (Get-Content -Raw 'd:\SourceCode\Hdf\hdf-dev-stack.yml') -replace "`r`n", "`n"
$body = [System.Text.Encoding]::UTF8.GetBytes((@{
  StackFileContent = $compose
  Env = @()
  PullImage = $true
  Prune = $true
} | ConvertTo-Json -Depth 5 -Compress))
Invoke-RestMethod -Uri 'https://103.176.179.103:9443/api/stacks/9?endpointId=3' -Method Put -Body $body -ContentType 'application/json; charset=utf-8' -Headers $headers

# Prod (Stack ID 3 — hdf-identity):
# Tương tự nhưng dùng compose file của identity prod và Stack ID 3
```

### Bước 4: Xác nhận

```powershell
$containers = Invoke-RestMethod -Uri 'https://103.176.179.103:9443/api/endpoints/3/docker/containers/json' -Headers $headers
# Dev:  $containers | Where-Object { $_.Names[0] -eq '/hdf-identity-test' } | Select-Object State, Status
# Prod: $containers | Where-Object { $_.Names[0] -eq '/hdf-identity' } | Select-Object State, Status
```

## Lưu ý quan trọng

1. **KHÔNG** deploy nhầm môi trường — luôn xác nhận tag (`:dev` hay `:prod`)
2. Cùng 1 Dockerfile, chỉ khác tag — runtime config khác nhau qua environment variables trên Portainer
3. Stack `hdf-dev` (ID 9) chứa cả DB + Identity + API — khi update sẽ restart tất cả services
4. Stack `hdf-identity` (ID 3) chỉ chứa Identity — chỉ restart Identity container
5. Luôn dùng `PullImage: true` để Portainer pull image mới nhất từ Docker Hub
6. **Build context** phải ở `CrediFlow.Identity/` (nơi có Dockerfile), KHÔNG phải root của hdf-identity
