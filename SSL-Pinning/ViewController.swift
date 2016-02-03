//
//  ViewController.swift
//  SSL-Pinning
//
//  Created by Ante Karin on 03/02/16.
//  Copyright © 2016 Ante Karin. All rights reserved.
//

import UIKit
import Alamofire

class ViewController: UIViewController, NSURLSessionDelegate, NSURLSessionTaskDelegate {

    @IBOutlet weak var urlTextField: UITextField!
    @IBOutlet weak var responseTextView: UITextView!
    
    var urlSession: NSURLSession?
    var serverTrustPolicy: ServerTrustPolicy?
    var afManager : Manager!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        //Configure NSURLSession
        
        urlSession = NSURLSession(configuration: NSURLSessionConfiguration.defaultSessionConfiguration(), delegate: self, delegateQueue: nil)
        
        //Configure NSURLSession
        
        self.serverTrustPolicy = ServerTrustPolicy.PinCertificates(
            certificates: ServerTrustPolicy.certificatesInBundle(NSBundle.mainBundle()),
            validateCertificateChain: true,
            validateHost: true
        )
        
        let serverTrustPolicies:[String: ServerTrustPolicy] = [
            "github.com": self.serverTrustPolicy!
        ]
        
        self.afManager = Alamofire.Manager(
            configuration: NSURLSessionConfiguration.defaultSessionConfiguration(),
            serverTrustPolicyManager: ServerTrustPolicyManager(policies: serverTrustPolicies)
        )
    }

    // MARK : Button actions
    
    @IBAction func alamoFireRequestHandler(sender: UIButton) {
        self.afManager.request(.GET, self.urlTextField.text!)
            .responseString { response in
                if let json = response.result.value {
                    self.responseTextView.text = json
                }
                print(response.response?.statusCode)
        }
    }
    
    @IBAction func nsurlSessionRequestHandler(sender: UIButton) {
        self.urlSession?.dataTaskWithURL(NSURL(string:self.urlTextField.text!)!, completionHandler: { (NSData data, NSURLResponse response, NSError error) -> Void in
            if let _ = data {
                dispatch_async(dispatch_get_main_queue(), { () -> Void in
                    self.responseTextView.text = String(data: data!, encoding: NSUTF8StringEncoding)
                    self.responseTextView.textColor = UIColor.blackColor()
                })
            }
            
            if let _ = error {
                dispatch_async(dispatch_get_main_queue(), { () -> Void in
                    self.responseTextView.text = error?.description
                    self.responseTextView.textColor = UIColor.redColor()
                })
            }
            
        }).resume()
    }
    
    // MARK: URL session delegate
    
    func URLSession(session: NSURLSession, didReceiveChallenge challenge: NSURLAuthenticationChallenge, completionHandler: (NSURLSessionAuthChallengeDisposition, NSURLCredential?) -> Void) {
        let serverTrust = challenge.protectionSpace.serverTrust
        let certificate = SecTrustGetCertificateAtIndex(serverTrust!, 0)
        
        // Set SSL policies for domain name check
        let policies = NSMutableArray();
        policies.addObject(SecPolicyCreateSSL(true, (challenge.protectionSpace.host)))
            SecTrustSetPolicies(serverTrust!, policies);
            
        // Evaluate server certificate
        var result: SecTrustResultType = 0
        SecTrustEvaluate(serverTrust!, &result)
        let isServerTrusted:Bool = (Int(result) == kSecTrustResultUnspecified || Int(result) == kSecTrustResultProceed)
        
        // Get local and remote cert data
        let remoteCertificateData:NSData = SecCertificateCopyData(certificate!)
        let pathToCert = NSBundle.mainBundle().pathForResource("github.com", ofType: "cer")
        let localCertificate:NSData = NSData(contentsOfFile: pathToCert!)!
        
        if (isServerTrusted && remoteCertificateData.isEqualToData(localCertificate)) {
            let credential:NSURLCredential = NSURLCredential(forTrust: serverTrust!)
            completionHandler(.UseCredential, credential)
        } else {
            completionHandler(.CancelAuthenticationChallenge, nil)
        }
    }
    
}

