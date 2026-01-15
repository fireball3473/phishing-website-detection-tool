import pandas as pd

class TrancoService:
    def __init__(self, file_path='datasets/tranco_trust_list.csv'):
        self.trusted_domains = set()
        try:
            # If there are no column names, we use header=None
            # Column a (index 0) is the number, column b (index 1) is the domain
            df = pd.read_csv(file_path, header=None)
            self.trusted_domains = set(df[1].str.lower().str.strip().tolist())
            print(f"Trusted Domain List Loaded: {len(self.trusted_domains)} trusted sites in memory.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def is_trusted(self, domain):
        # Exact domain match or root domain control
        return domain in self.trusted_domains

# Creating a global instance
tranco_checker = TrancoService()