# Timelock Encryption

Proof of concept to demonstrate timelock encryption with Drand DKG for prevent front running attacks in blockchain.

## Configuration
DRand public parameters needs to configured at ``config/default.json``
```
{
   "chainHash":"43d4784e9aa3db960d120b3553353be5b6635d7a95bf88831561dfdb3c7c8099",
   "urls":[
      "http://127.0.0.5:39111"
   ]
}
```
## Running locally
To run it locally, you would require the latest version of ``nodejs`` and ``npm``. 

```
git clone https://github.com/Spockuto/timelock.git
cd timelock
npm install
npm start
```
Visit the website at ``localhost:5000``