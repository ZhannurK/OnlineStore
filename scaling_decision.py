def set_scaling_thresholds(predicted_traffic):
    BASE_RPM = 10000
    SCALE_UP_THRESHOLD = 0.8
    SCALE_DOWN_THRESHOLD = 0.5

    scale_up = BASE_RPM * SCALE_UP_THRESHOLD
    scale_down = BASE_RPM * SCALE_DOWN_THRESHOLD

    if predicted_traffic > scale_up:
        return "Scale Up"
    elif predicted_traffic < scale_down:
        return "Scale Down"
    else:
        return "Maintain Current Infrastructure"

# Example usage
predicted_rpm = 15000  # Replace with real prediction
decision = set_scaling_thresholds(predicted_rpm)
print(f"Decision: {decision}")
