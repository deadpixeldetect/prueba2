# Sentinel NGFW — Simulador de Firewall de Nueva Generación

## Ejecutar
    pip install -r requirements.txt
    python app.py
Abrir http://localhost:5000

## Funcionalidades
- Dashboard en tiempo real: conexiones, bloqueos, amenazas, gráficos L7
- Reglas ordenadas estilo Palo Alto / FortiGate (origen, destino, app, acción, perfiles IPS/WebFilter)
- Motor de políticas con default-deny y matching por CIDR
- Registro de tráfico en vivo con clasificación de aplicaciones y amenazas
- Simulador "policy tester" para evaluar flujos contra la política
- Generador de tráfico sintético en segundo plano (thread daemon)

## API
- GET  /api/stats      métricas agregadas
- GET|POST /api/rules  listar / crear reglas
- PUT|DELETE /api/rules/<id>  habilitar-editar / eliminar
- GET  /api/logs       últimos 40 eventos
- POST /api/test       evaluar un flujo contra la política
