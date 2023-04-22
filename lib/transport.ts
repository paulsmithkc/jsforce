import request, { Response } from 'request';
// const jsonp = require('./browser/jsonp');
// const canvas = require('./browser/canvas');

// set options if defaults setting is available in request, which is not available in xhr module.
let requestWithDefaults = request;
if (request.defaults) {
  const defaults: any = {
    followAllRedirects: true
  };
  
  const proxy = process.env.HTTP_PROXY;
  if (proxy) { defaults.proxy = proxy; }
  
  const timeout = parseInt(process.env.HTTP_TIMEOUT || '', 10);
  if (timeout) { defaults.timeout = timeout; }

  requestWithDefaults = request.defaults(defaults);
}

// let baseUrl: string;
// if (typeof window === 'undefined') {
//   baseUrl = process.env.LOCATION_BASE_URL || "";
// } else {
//   var apiHost = window.location.host;
//   {
//     // Normalize Salesforce API host name
//     const match = /(\w+)\.(visual\.force|salesforce)\.com$/.exec(apiHost);
//     if (match) {
//       apiHost = match[1] + ".salesforce.com";
//     }
//   }
//   baseUrl = apiHost ? "https://" + apiHost : "";
// }

/** Add stream() method to promise (and following promise chain), to access original request stream. */
// function streamify(promise: any, factory: any): any {
//   const _then = promise.then;
//   promise.then = function () {
//     factory();
//     const newPromise = _then.apply(promise, arguments);
//     return streamify(newPromise, factory);
//   };
//   promise.stream = factory;
//   return promise;
// }

export class Transport {
  constructor() {}

  httpRequest(params: any): Promise<Response> {
    const httpRequest = this._getHttpRequestModule();
    return new Promise<Response>((resolve, reject) => {
      httpRequest(params, (err: any, response: Response) => {
        if (err) {
          reject(err);
        } else {
          resolve(response);
        }
      });
    });
  }

  protected _getHttpRequestModule(): typeof request {
    return requestWithDefaults;
  };
}

// /** 
//  * Class for JSONP request transport 
//  */
// export class JsonpTransport extends Transport {
//   private _jsonpParam: string;

//   /**
//    * @param jsonpParam - Callback parameter name for JSONP invocation.
//    */
//   constructor(jsonpParam: string) {
//     super();
//     this._jsonpParam = jsonpParam;
//   }

//   protected _getHttpRequestModule() {
//     return jsonp.createRequest(this._jsonpParam);
//   };

//   get supported() {
//     return jsonp.supported;
//   } 
// }


// /**
//  * Class for Sfdc Canvas request transport
//  */
// export class CanvasTransport extends Transport {
//   private _signedRequest: string;

//   /**
//    * @param signedRequest - Parsed signed request object
//    */
//   constructor(signedRequest: any) {
//     super();
//     this._signedRequest = signedRequest;
//   }

//   protected _getHttpRequestModule() {
//     return canvas.createRequest(this._signedRequest);
//   }

//   get supported() {
//     return canvas.supported;
//   } 
// }
