import joblib

# Load Model
model = joblib.load('phishing_model.joblib')

# Print the model type and parameters
print(type(model))
print(model.get_params())
