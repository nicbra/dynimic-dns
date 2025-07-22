# Domeneshop dynamic IP updater
Make sure you create an `.env`-file. It should contain these environmental variables:
- `TOKEN`: API token from Domeneshop
- `SECRET`: API secret from Domeneshop
- `ADDRESS`: String contaning the address to update. Ex.: `"example.com"`


## Example Docker Compose YAML
```yaml
services:
  domeneshop:
    container_name: domeneshop
    build:
      context: ./domeneshop
      dockerfile: Dockerfile
    restart: unless-stopped
    volumes:
    - /home/name/dynimic-ip/.env:/.env
    - /home/name/dynimic-ip/ddns.py:/ddns.py
    command: python3 ddns.py
```