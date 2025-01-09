import os
import requests
import json
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

# Constants
URL = "https://gov-portal-verifier-api.ambrosus-test.io/db/rewards"
LIMIT = 100

def hex_to_int(hex_value):
    return int(hex_value, 16)

def fetch_rewards(token):
    start_index = 0
    total_rewards = 0
    fetched_total_rewards = 0

    headers = {
        "Content-Type": "application/json"
    }

    while True:
        # Prepare the request payload
        payload = {
            "token": token,
            "start": start_index,
            "limit": LIMIT,
            "output": "json"
        }

        # Make the POST request
        response = requests.post(URL, headers=headers, json=payload)

        if response.status_code != 200:
            raise Exception(f"Failed to fetch data: {response.status_code} {response.text}")

        data = response.json()

        fetched_total_rewards = hex_to_int(data.get("totalRewards", 0));

        # Process the data entries
        for entry in data.get("data", []):
            rewards_by_wallet = entry.get("rewardsByWallet", {})
            batch_status = entry.get("status")

            for wallet_data in rewards_by_wallet.values():
                reward_status = wallet_data.get("status")
                reward_amount = hex_to_int(wallet_data["amount"])

                if reward_status == "claimed" or (reward_status is None and batch_status is None):
                    total_rewards += reward_amount
                else:
                    print(f"ignore reward (id: {entry.get("id")}, wallet: {wallet_data.get("wallet")}, amount: {Web3.from_wei(reward_amount, 'ether')}). entry status: {batch_status} reward status: {reward_status}")

        # Update start_index for pagination
        start_index += len(data.get("data", []))

        # Stop when we've processed all entries
        if start_index >= data.get("total", 0):
            break

    return total_rewards, fetched_total_rewards

if __name__ == "__main__":
    # Replace with your actual JWT token
    jwt_token = os.getenv('SESSION_TOKEN')

    try:
        total_amount, fetched_total_amount = fetch_rewards(jwt_token)
        print(f"Total rewards amount: {Web3.from_wei(total_amount, 'ether')} ETH ({Web3.from_wei(fetched_total_amount, 'ether')} ETH)")
    except Exception as e:
        print(f"Error: {e}")