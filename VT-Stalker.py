import requests
import json


def get_comments(user):
    # This response contains json data that includes the file hash, as well as the 'cursor' link to get more hashes
    # Store in the same sqlite database as the Threat Grid data
    # Eventually move all that sqlite data to MISP
    url = 'https://www.virustotal.com/ui/users/itsreallynick/comments'

    headers = {
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9'
    }

    r = requests.get(url, headers=headers, verify=False)
    encoded_json = json.JSONEncoder().encode(r.text)
    json_data = eval(json.loads(encoded_json))
    # for x in json_data.keys():
    #     print(x)
    for x in json_data['data']:
        note = x['attributes']['html'].encode(encoding='UTF-16')
        id_hash = x['id'].encode(encoding='UTF-16')
        print(note, id_hash)
    # print(json_data['links'])

if __name__ == '__main__':
    users = [
        'itsreallynick',
        'tuantmbk'
        ]
    for user in users:
        get_comments(user)