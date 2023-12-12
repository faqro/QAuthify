<img src="https://raw.githubusercontent.com/faqro/qauthify/master/src/qauthify-logo.png" height="100"/>
# QAuthify
 
Lightweight and open-source JWT-based SSO auth platform. Made with Node.js, Express, and MongoDB.

Note: You should use https for all production deployments, to prevent passwords from being exposed. SSL and https implementation is the responsibility of the end user.

This should only really be used for situations where a single purpose or single domain auth platform is insufficient.

To do:
- [X] Basic setup
- [X] Refresh token setup (login, auth verify for resource access, logout) (MongoDB should store userID, list of refresh tokens & date of last usage & location of last usage & ip of last usage, )
- [X] Fully implement MongoDB (including SSL)
- [X] Delete account feature
- [X] Refresh token expiration (optional)
- [X] Credential validation (username, password) with MongoDB
- [ ] Cross-domain SSO (access cookies/localstorage from subdomain setup?)
- [X] SSL/HTTPS (serve SSL from Express)
- [X] Prevent ID overlap