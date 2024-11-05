"""
/*
 * This file is part of the oppo_metrics distribution (https://github.com/CTTCTech/oppo_metrics).
 * Copyright (c) 2024 Centre Tecnològic de Telecomunicacions de Catalunya (CTTC).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
"""

from OppoServer import OppoServer
from credentials import *
from fastapi import FastAPI, Request
from fastapi.responses import  JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from cachetools import TTLCache


limiter = Limiter(key_func=lambda request: request.client.host)
app = FastAPI()

# add the static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up a cache, time-to-live 5 seconds
cache = TTLCache(maxsize=1, ttl=5)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    # Check if there is cached data to return when rate limit is exceeded
    if "latest_data" in cache:
        return JSONResponse(
            status_code=200,
            content=cache["latest_data"],
        )
    else:
        return JSONResponse(
            status_code=429,
            content={
                "error code": 1,
                "detail": "Too many requests (1 per 5 seconds). Please wait and try again."},
        )



@app.get("/api/metrics")
@limiter.limit("1/5second")  # Limit to 1 request every 5 seconds
async def get_metrics(request: Request):
    # Replace these with actual values or a function to fetch real metrics
    try:
        data = request_metrics()

        # Update cache with the latest data
        cache["latest_data"] = data

        return data
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to fetch metrics", "details": str(e)},
        )
def request_metrics():
    oppo = OppoServer(
        base_url=BASE_URL,
        username=USERNAME,
        password=PASSWORD
    )
    
    config_msg = oppo.webconfig()

    resp = oppo.token_status()

    resp = oppo.nas_signal_info()
    return resp
    
# show the index.html file at the root URL
@app.get("/", response_class=FileResponse)
async def read_root():
    return "static/index.html"


@app.get("/metrics-url")
async def get_metrics_url(request: Request):
    # Generate the full URL for the metrics endpoint
    base_url = request.url.scheme + "://" + request.url.hostname + ":" + str(request.url.port)
    metrics_url = f"{base_url}/api/metrics"
    return {"metrics_url": metrics_url}
def main():
    oppo = OppoServer(
        base_url=BASE_URL,
        username=USERNAME,
        password=PASSWORD
    )
    
    config_msg = oppo.webconfig()
    #print(json.dumps(config_msg))

    resp = oppo.token_status()
    print(resp)
    
    resp = oppo.nas_signal_info()
    print(resp)

if __name__ == "__main__":
    main()



'''
resp = oppo.nas_signal_info()
{'4G': {'AvgRsrp': -81, 'Rsrp': -81, 'Rsrq': -15, 'Rssi': -49, 'Sinr': 2}, 
 '5G': {'AvgRsrp': -110, 'Rsrp': -113, 'Rsrq': -11, 'Sinr': 8}, 'ErrorCode': 0, 'NetMode': '5G'}
'''