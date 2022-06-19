from bs4 import BeautifulSoup
from urllib.request import Request, urlopen

#webcrwaler to return directory traversal links
def crawler(url):
    if(len(url)==0):
        return 'Enter a valid link' 
    try:
        links=[]
        # Sending request to server using BeautifulSoup
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        html_data = urlopen(req).read()
        
        #Beautyfying all data to html form 
        soup=BeautifulSoup(html_data,'html.parser')

        #Retriving all anchor tags in html data
        tags=soup('a')

        #Adding all href attribute values to list
        for tag in tags:
                if tag.has_attr('href'):
                    links.append(tag['href'])
        return(links)
        
    except:
        #Check if any errors
        return 'Please check the URL properly' 