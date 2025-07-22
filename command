docker system prune -f
docker system prune -a --volumes -f
docker builder prune -a -f
docker compose up --build -d
docker compose logs -f
docker compose down -v
