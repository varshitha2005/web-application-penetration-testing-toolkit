import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

HEADERS = {"User-Agent": "PentestBot/1.0"}

def find_endpoints(base_url):
    """MAIN FUNCTION - Called by app.py"""
    results = {
        "found": False,
        "endpoints": [],
        "forms": [],
        "params": [],
        "priority_pages": []
    }
    
    # Use YOUR existing crawler
    urls = crawl_website(base_url, max_pages=5)
    
    # Extract useful info from crawled pages
    all_params = []
    for url in urls:
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")
            
            # Find forms & parameters
            forms = soup.find_all("form")
            for form in forms:
                inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                if inputs:
                    results["forms"].append({
                        "url": url,
                        "params": inputs[:3]
                    })
                    all_params.extend(inputs)
                    results["endpoints"].append(url)
            
            results["priority_pages"] = urls
            results["params"] = list(set(all_params))
            
            if forms or all_params:
                results["found"] = True
                
        except:
            continue
    
    print(f"✅ Crawler found {len(results['forms'])} forms!")
    return results

# YOUR ORIGINAL CODE (KEEP EXACTLY AS IS - it's perfect!)
def crawl_website(base_url, max_pages=3):
    visited = set()
    queue = [base_url]
    urls = []
    
    domain = urlparse(base_url).netloc
    
    # PRIORITY PAGES for pentesting
    priority_paths = ['/', '/login', '/search', '/admin', '/user', '/api', '/test']
    
    while queue and len(urls) < max_pages:
        url = queue.pop(0)
        
        if url in visited:
            continue
        visited.add(url)
        urls.append(url)
        
        try:
            print(f"   Fetching: {url}")
            r = requests.get(url, timeout=5, headers={"User-Agent": "PentestBot/1.0"})
            
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                
                # Find forms (vulnerable to SQLi/XSS)
                forms = soup.find_all("form")
                print(f"   Found {len(forms)} forms")
                
                # Find common vuln links
                for link in soup.find_all("a", href=True)[:10]:
                    href = link["href"]
                    new_url = urljoin(base_url, href)
                    
                    # Stay on same domain
                    if (urlparse(new_url).netloc == domain and 
                        new_url not in visited and 
                        len(urls) < max_pages):
                        
                        # Prioritize interesting paths
                        path = urlparse(new_url).path.lower()
                        if any(p in path for p in priority_paths):
                            queue.insert(0, new_url)  # Priority queue
                        else:
                            queue.append(new_url)
        except Exception as e:
            print(f"   Crawl error: {e}")
            continue
    
    print(f"✅ Crawling complete: {len(urls)} pages")
    return urls
