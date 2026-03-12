## Instructions

- Install Visual Code with C# support
- Open project via Ntag424DNA.csproj file

---

- Click - Step 1 Activate Ntag 424
- Click - Select Existing Card (Select Card App: 424 card ISO DF Name)
- Click - Key authentication (With Auth Key: 0)

---

- Select - Example 3
- Title: (optional, blank for iOS)
- Prefix: https:// or http://
- Set url e.g. localhost/?picc_data=00000000000000000000000000000000&cmac=0000000000000000 and click the location wheres 0s start to get first and second offset)
- Check - Requires Auth Key, Key no - 0
- Comm Mode - Plaintext
- Click - Write URI to card

---

- Click - Key authentication (With Auth Key: 0)
- Select - Enable SDM Mirror, Enable UID Mirror, Enable Counter Mirror (Keep both keys to 0 if you want to use master for encryption)
- Set - PICCDataOffset and SDMMACInputOffset to first zero position (e.g. 44); and SDMMACOffset to second zero offset (e.g. 82)

- Set - UID mirror offset and everything else below to 0
- SDM Counter retrieval - Disabled
- Ensure 'Comm Mode for This Operation' is set to - Encrypted + Mac protocol
- Click - Modify Card configuration