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

    let githubCert = "github.com"
    let corruptedCert = "corrupted"
    
    @IBOutlet weak var urlTextField: UITextField!
    @IBOutlet weak var responseTextView: UITextView!
    @IBOutlet weak var certificateCorruptionButton: UIButton!
    @IBOutlet weak var activityIndicator: UIActivityIndicatorView!
    
    var urlSession: NSURLSession!
    var serverTrustPolicy: ServerTrustPolicy!
    var serverTrustPolicies: [String: ServerTrustPolicy]!
    var afManager : Manager!
    
    var isSimulatingCertificateCorruption: Bool?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let pathToCert = NSBundle.mainBundle().pathForResource(githubCert, ofType: "cer")
        let localCertificate:NSData = NSData(contentsOfFile: pathToCert!)!
        self.configureAlamoFireSSLPinningWithCertificateData(localCertificate)
        self.configureURLSession()
        
        self.activityIndicator.hidesWhenStopped = true
    }
    
    // MARK: Button actions
    
    @IBAction func alamoFireRequestHandler(sender: UIButton) {
        self.activityIndicator.startAnimating()
        self.afManager.request(.GET, self.urlTextField.text!)
            .response { request, response, data, error in
                if error == nil {
                    if let responseData = data {
                        self.responseTextView.text = String(data: responseData, encoding: NSUTF8StringEncoding)!
                    }
                    self.responseTextView.textColor = UIColor.blackColor()
                } else {
                    self.responseTextView.text = error?.description
                    self.responseTextView.textColor = UIColor.redColor()
                }
                self.activityIndicator.stopAnimating()
        }
    }
    
    @IBAction func nsurlSessionRequestHandler(sender: UIButton) {
        self.activityIndicator.startAnimating()
        self.urlSession?.dataTaskWithURL(NSURL(string:self.urlTextField.text!)!, completionHandler: { (NSData data, NSURLResponse response, NSError error) -> Void in
            dispatch_async(dispatch_get_main_queue(), { () -> Void in
                self.activityIndicator.stopAnimating()
                })
            
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
    
    @IBAction func toggleCertificateSimulation(sender: AnyObject) {
        if self.isSimulatingCertificateCorruption != nil {
            self.isSimulatingCertificateCorruption = nil;
            let pathToCert = NSBundle.mainBundle().pathForResource(githubCert, ofType: "cer")
            let localCertificate:NSData = NSData(contentsOfFile: pathToCert!)!
            self.configureAlamoFireSSLPinningWithCertificateData(localCertificate)
            self.certificateCorruptionButton.setTitleColor(self.certificateCorruptionButton.tintColor, forState: UIControlState.Normal)
            self.certificateCorruptionButton.setTitle("Simulate certificate corruption", forState: UIControlState.Normal)
        } else {
            self.isSimulatingCertificateCorruption = true
            let pathToCert = NSBundle.mainBundle().pathForResource(corruptedCert, ofType: "cer")
            let localCertificate:NSData = NSData(contentsOfFile: pathToCert!)!
            self.configureAlamoFireSSLPinningWithCertificateData(localCertificate)
            self.certificateCorruptionButton.setTitleColor(UIColor.redColor(), forState: UIControlState.Normal)
            self.certificateCorruptionButton.setTitle("Simulating certificate corruption", forState: UIControlState.Normal) 
        }
    }
    // MARK: SSL Config
    
    func configureAlamoFireSSLPinningWithCertificateData(certificateData: NSData) {
        self.serverTrustPolicy = ServerTrustPolicy.PinCertificates(
            certificates: [SecCertificateCreateWithData(nil, certificateData)!],
            validateCertificateChain: true,
            validateHost: true
        )
        
        self.serverTrustPolicies = [
            "github.com": self.serverTrustPolicy!
        ]
        
        self.afManager = Manager(
            configuration: NSURLSessionConfiguration.defaultSessionConfiguration(),
            serverTrustPolicyManager: ServerTrustPolicyManager(policies: self.serverTrustPolicies)
        )
    }
    
    func configureURLSession() {
        self.urlSession = NSURLSession(configuration: NSURLSessionConfiguration.defaultSessionConfiguration(), delegate: self, delegateQueue: nil)
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
        let pathToCert = NSBundle.mainBundle().pathForResource(githubCert, ofType: "cer")
        let localCertificate:NSData = NSData(contentsOfFile: pathToCert!)!
        
        if (isServerTrusted && remoteCertificateData.isEqualToData(localCertificate)) {
            let credential:NSURLCredential = NSURLCredential(forTrust: serverTrust!)
            completionHandler(.UseCredential, credential)
        } else {
            completionHandler(.CancelAuthenticationChallenge, nil)
        }
    }
    
}

