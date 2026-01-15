import whois
from datetime import datetime

def get_domain_age_days(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            # Removing the time zone information (replace(tzinfo=None)) [This prevents offset-naive and offset-aware conflicts.]
            creation_date = creation_date.replace(tzinfo=None)
            now = datetime.now().replace(tzinfo=None)
            
            age = (now - creation_date).days
            return age
        return None
    except Exception as e:
        print(f"Whois Error ({domain}): {e}")
        return None