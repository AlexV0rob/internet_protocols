import socket
import argparse
import os
import json
from datetime import datetime, timezone, timedelta


def get_wind_direction(degree):
    directions = ["north", "northeast", "east", "southeast",
                  "south", "southwest", "west", "northwest"]
    return directions[(int(degree + 22.5) % 360) // 45]

def get_string_or_nothing(data, *args):
    try:
        elem = data
        for arg in args:
            elem = elem[arg]
        return elem
    except (KeyError, IndexError):
        return "_"

def parse_forecast_data(data):
    parsed = {}
    parsed["timezone"] = get_string_or_nothing(data, "timezone")
    parsed["dt"] = get_string_or_nothing(data, "dt")
    parsed["sunrise"] = get_string_or_nothing(data, "sys", "sunrise")
    parsed["sunset"] = get_string_or_nothing(data, "sys", "sunset")
    parsed["weather"] = get_string_or_nothing(data, "weather", 0, "main")
    parsed["desc"] = get_string_or_nothing(data, "weather", 0, "description")
    parsed["wind_deg"] = get_string_or_nothing(data, "wind", "deg")
    parsed["city"] = get_string_or_nothing(data, "name")
    parsed["country"] = get_string_or_nothing(data, "sys", "country")
    parsed["temp_main"] = get_string_or_nothing(data, "main", "temp")
    parsed["temp_min"] = get_string_or_nothing(data, "main", "temp_min")
    parsed["temp_max"] = get_string_or_nothing(data, "main", "temp_max")
    parsed["temp_feels"] = get_string_or_nothing(data, "main", "feels_like")
    parsed["pressure"] = get_string_or_nothing(data, "main", "pressure")
    parsed["humidity"] = get_string_or_nothing(data, "main", "humidity")
    parsed["wind_speed"] = get_string_or_nothing(data, "wind", "speed")
    parsed["clouds"] = get_string_or_nothing(data, "clouds", "all")
    return parsed

def get_date(value, tz, imperial_units):
    dt_format = ("%m-%d-%Y %H:%M:%S" 
                 if imperial_units 
                 else "%d.%m.%Y %H:%M:%S")
    if value:
        return datetime.fromtimestamp(value, tz=tz).strftime(dt_format)
    return "_"

def create_forecast(data, imperial_units):
    deg = ("*F" if imperial_units else "*C")
    speed = ("miles/hour" if imperial_units else "meters/sec")
    parsed = parse_forecast_data(data)
    try:
        tz = timezone(timedelta(seconds=parsed["timezone"]))
    except (TypeError, ValueError):
        tz = None
    date = get_date(parsed["dt"], tz, imperial_units)
    sunrise = get_date(parsed["sunrise"], tz, imperial_units)
    sunset = get_date(parsed["sunset"], tz, imperial_units)
    try:
        pressure = round(float(parsed["pressure"]) / 1.3333, 2)
    except (TypeError, ValueError):
        pressure = "_"
    return f"""Forecast for {parsed["city"]}, {parsed["country"]} for {date}
Weather:      {parsed["weather"]} ({parsed["desc"]})
Temperature: 
  main:       {parsed["temp_main"]} {deg}
  min:        {parsed["temp_min"]} {deg}
  max:        {parsed["temp_max"]} {deg}
  feels like: {parsed["temp_feels"]} {deg}
Athmosperic
pressure:     {pressure} mmHg
Humidity:     {parsed["humidity"]}%
Wind:
  speed:      {parsed["wind_speed"]} {speed}
  direction:  {get_wind_direction(parsed["wind_deg"])} ({parsed["wind_deg"]}*)
Clouds:       {parsed["clouds"]}%
Sunrise:      {sunrise}
Sunset:       {sunset}"""

def get_weather(city, country, date, imperial_units):
    host = "api.openweathermap.org"
    port = 80
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    place_query = f"q={city}"
    if country is not None:
        place_query += f",{country.replace(' ', '_')}"
    date_query = ""
    if date is not None:
        date_parts = date.split('.')
        date_parts.reverse()
        date_query = f"date={'-'.join(date_parts)}"
    appid = f"appid={os.getenv("WEATHER_API_KEY")}"
    if imperial_units:
        units_query = f"units=imperial"
    else:
        units_query = f"units=metric"
    query_parts = [place_query, appid, units_query]
    if date_query:
        query_parts.append(date_query)
    request = f"/data/2.5/weather?{'&'.join(query_parts)}"
    sock.send(f"GET {request} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    response = ""
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            response += data.decode()
        except socket.error:
            break
    if response:
        header, body = response.split("\r\n\r\n", 1)
        info = json.loads(body)
        if header.split("\r\n", 1)[0].upper().startswith("HTTP/1.1 4"):
            print(f"Couldn't retrieve data from openwheathermap.org: "
                  f"{info["message"]}")
        else:
            print(create_forecast(info, imperial_units))
    else:
        print("Something went wrong. Try again later")

def main():
    parser = argparse.ArgumentParser(
        prog="http weather", 
        description="Get weather information"
    )
    parser.add_argument("city", type=str, 
                        help="City")
    parser.add_argument("-c", "--country", type=str, 
                        help="Country")
    parser.add_argument("-d", "--date", type=str, 
                        help="Date (unimplemented)")
    parser.add_argument("-u", "--units", action="store_true",
                        help="Use imperial units")
    args = parser.parse_args()
    get_weather(args.city, args.country, args.date, args.units)

if __name__ == "__main__":
    main()
