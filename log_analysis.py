from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

# Connect to Elasticsearch
es = Elasticsearch([{"host": "localhost", "port": 9200, "scheme": "http"}])

def count_logs(start, end):
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": start,
                    "lt": end
                }
            }
        }
    }
    return es.count(index="server_logs", body=query)["count"]

def get_monthly_growth():
    now = datetime.utcnow()
    this_month_start = now.replace(day=1).isoformat()
    last_month_end = this_month_start
    last_month_start = (now.replace(day=1) - timedelta(days=1)).replace(day=1).isoformat()

    last_count = count_logs(last_month_start, last_month_end)
    curr_count = count_logs(this_month_start, now.isoformat())

    if last_count == 0:
        return 0
    return ((curr_count - last_count) / last_count) * 100

def predict_traffic(curr_count, growth_rate):
    forecasts = []
    for i in range(6):
        curr_count += curr_count * (growth_rate / 100)
        forecasts.append(int(curr_count))
    return forecasts

if __name__ == "__main__":
    growth = get_monthly_growth()
    current_month_start = datetime.utcnow().replace(day=1).isoformat()
    current_logs = count_logs(current_month_start, datetime.utcnow().isoformat())
    predictions = predict_traffic(current_logs, growth)

    print(f"Growth Rate: {growth:.2f}%")
    print("Forecast for next 6 months:")
    for i, value in enumerate(predictions, start=1):
        print(f"Month {i}: {value} log entries")
