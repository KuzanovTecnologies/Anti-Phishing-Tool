#Get_Domain

from urllib.parse import urlparse 

def get_domain(url):
    """
    Extracts the domain name from a given URL, normalizing it. 
    
    Args:
        url (str): The URL string to process. 
        
    Returns:
        str: The normalized domain (e.g., example.com)
        """
    if not url.startswith("http"):
            url = "http://" + url

    try: 
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove 'www.' prefix if present
            if domain.startswith("www."):
                domain = domain[4:]

            return domain 
    except Exception as e:
            print(f"[Error] Failed to parse domain: {e}")
            return None
    
    # Example usage 
    if __name__ == "__main__":
          test_urls = [
              "http://amazon-international.cc",
              "https://comssgptomsjira.amazon-relay.com",
              "http://amazon-clone-42hz626aw-kunal838.vercel.app",
              "https://amazon-relay.comoltyhssjira.amazon-relay.com",
          ]

          for url in test_urls:
                print(f"Input: {url} -> Domain: {get_domain(url)}")

from get_domain import get_domain