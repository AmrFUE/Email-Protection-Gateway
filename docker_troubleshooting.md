# EPG Docker Troubleshooting Guide

This guide contains the essential Docker commands needed to monitor, troubleshoot, and restart the various layers of the Email Protection Gateway (EPG) pipeline.

## 1. Viewing Live Logs (Tailing)

To view what a container is currently doing, use the `docker logs -f` command. The `-f` flag "follows" the logs so you can see new lines as they appear in real-time. Press `Ctrl+C` to stop tailing.

- **Orchestrator (Main Pipeline Router):**
  ```powershell
  docker logs -f epg-orchestrator
  ```
  *Use this to see how an email flows through the system and whether the dynamic sandbox is skipped or used.*

- **Static Malware Scanner:**
  ```powershell
  docker logs -f epg-malware
  ```

- **Phishing Filter:**
  ```powershell
  docker logs -f epg-phishing
  ```

- **Spam Filter:**
  ```powershell
  docker logs -f epg-spam
  ```

- **Dashboard:**
  ```powershell
  docker logs -f epg-dashboard
  ```

## 2. Checking Container Status

To see which containers are currently running, their uptime, and their health status:
```powershell
docker ps
```

To see all containers, including ones that have crashed or stopped:
```powershell
docker ps -a
```

## 3. Restarting Containers

If a specific layer is unresponsive or you have made changes to the code, you can restart the container:

- **Restart a single layer (e.g., Phishing):**
  ```powershell
  docker restart epg-phishing
  ```

- **Rebuild and restart a layer after changing its code:**
  ```powershell
  docker compose up -d --build phishing-filter
  ```
  *(Run this from `D:\New_EGPInAzure\EGPInAzure` where the `docker-compose.yml` is located)*

## 4. Rebuilding the Entire System

If you want to apply all your latest code changes and restart the entire system from scratch:
```powershell
docker compose down
docker compose up -d --build
```
*(This will shut down all containers, rebuild any changed images, and start everything in the background).*

## 5. Investigating Issues Inside a Container

Sometimes you need to look at files inside the container itself. You can open a shell inside a running container using `docker exec`:

```powershell
docker exec -it epg-orchestrator /bin/bash
```
*(Type `exit` to leave the container's terminal when you are done).*

## 6. Fixing "Port Already in Use" Errors
If you try to start the system but get an error that a port is already in use, you can stop all running containers:
```powershell
docker stop $(docker ps -aq)
```
*(Note: Use this with caution as it stops every Docker container on your machine).*
