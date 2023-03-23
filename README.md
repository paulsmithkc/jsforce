# jsforce-micro

This is a fork of [jsforce](https://www.npmjs.com/package/jsforce) intended minimize the size of the package, and remove uncommon usages.

## Overview

JSforce is a JavaScript Library utilizing Salesforce's API.

It encapsulates the access to various APIs provided by Salesforce in asynchronous JavaScript function calls.

Supported Salesforce APIs are the following:

- TBD

## Documentation

See documentation in http://jsforce.github.io/ .

## License

See [license](LICENSE) (MIT License).

## Authors

- Shinichi Tomita
- Paul Smith

## Notes

If you have any questions first file it on [issues](https://github.com/paulsmithkc/jsforce/issues) before contacting authors via e-mail.

## Tests

In order to run tests you will need a [Salesforce Developer Org](https://developer.salesforce.com/signup)

You will also need to install the JsforceTestSuite package, which can be done by running:

    SF_USERNAME=myusername SF_PASSWORD=password+securityToken ./test/bin/org-setup

You may need to run this more then once if you encounter timeouts or dropped connections/

Finally, to run the tests simply do:

    SF_USERNAME=myusername SF_PASSWORD=password+securityToken npm run test:node

    SF_USERNAME=myusername SF_PASSWORD=password+securityToken npm run test:browser

## Contributions

Your contributions are welcome: both by reporting issues on [GitHub issues](https://github.com/paulsmithkc/jsforce/issues) or pull-requesting patches.

If you want to implement any additional features, to be added to JSforce to our master branch, which may or may not be merged please first check current [opening issues](https://github.com/paulsmithkc/jsforce/issues?q=is%3Aopen) with milestones and confirm whether the feature is on road map or not.

If your feature implementation is brand-new or fixing bugs in the library's test cases, please include additional test codes in the `test/` directory.
