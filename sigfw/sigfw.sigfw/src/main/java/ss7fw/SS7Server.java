/**
 * SigFW
 * Open Source SS7/Diameter firewall
 * By Martin Kacer, Philippe Langlois
 * Copyright 2017, P1 Security S.A.S and individual contributors
 * 
 * See the AUTHORS in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * 
 * Modified jSS7 SctpServer.java example
 */
package ss7fw;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.logging.Level;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.mobicents.protocols.api.Association;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.api.ManagementEventListener;
import org.mobicents.protocols.api.Server;
import org.mobicents.protocols.sctp.ManagementImpl;
import org.mobicents.protocols.ss7.indicator.NatureOfAddress;
import org.mobicents.protocols.ss7.indicator.RoutingIndicator;
import org.mobicents.protocols.ss7.m3ua.As;
import org.mobicents.protocols.ss7.m3ua.ExchangeType;
import org.mobicents.protocols.ss7.m3ua.Functionality;
import org.mobicents.protocols.ss7.m3ua.IPSPType;
import org.mobicents.protocols.ss7.m3ua.impl.AspImpl;
import org.mobicents.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.mobicents.protocols.ss7.m3ua.parameter.RoutingContext;
import org.mobicents.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.mobicents.protocols.ss7.map.MAPStackImpl;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContext;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextName;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextVersion;
import org.mobicents.protocols.ss7.map.api.MAPDialog;
import org.mobicents.protocols.ss7.map.api.MAPDialogListener;
import org.mobicents.protocols.ss7.map.api.MAPException;
import org.mobicents.protocols.ss7.map.api.MAPMessage;
import org.mobicents.protocols.ss7.map.api.MAPProvider;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortProviderReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortSource;
import org.mobicents.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic;
import org.mobicents.protocols.ss7.map.api.dialog.MAPRefuseReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
import org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.mobicents.protocols.ss7.map.api.primitives.AddressNature;
import org.mobicents.protocols.ss7.map.api.primitives.AddressString;
import org.mobicents.protocols.ss7.map.api.primitives.IMSI;
import org.mobicents.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.mobicents.protocols.ss7.map.api.primitives.LMSI;
import org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan;
import org.mobicents.protocols.ss7.map.api.primitives.USSDString;
import org.mobicents.protocols.ss7.map.api.service.lsm.AdditionalNumber;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.LocationInfoWithLMSI;
import org.mobicents.protocols.ss7.map.api.service.sms.MAPDialogSms;
import org.mobicents.protocols.ss7.map.api.service.sms.MAPServiceSmsListener;
import org.mobicents.protocols.ss7.map.api.service.sms.MoForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MoForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.MtForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MtForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.NoteSubscriberPresentRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReadyForSMRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReadyForSMResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_DA;
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_OA;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ActivateSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ActivateSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.DeactivateSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.DeactivateSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.EraseSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.EraseSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.GetPasswordRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.GetPasswordResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.InterrogateSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.InterrogateSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.MAPDialogSupplementary;
import org.mobicents.protocols.ss7.map.api.service.supplementary.MAPServiceSupplementaryListener;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterPasswordRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterPasswordResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSResponse;
import org.mobicents.protocols.ss7.map.datacoding.CBSDataCodingSchemeImpl;
import org.mobicents.protocols.ss7.sccp.LoadSharingAlgorithm;
import org.mobicents.protocols.ss7.sccp.OriginationType;
import org.mobicents.protocols.ss7.sccp.RuleType;
import org.mobicents.protocols.ss7.sccp.SccpProvider;
import org.mobicents.protocols.ss7.sccp.impl.SccpResourceImpl;
import org.mobicents.protocols.ss7.sccp.impl.SccpStackImpl;
import org.mobicents.protocols.ss7.sccp.impl.router.RouterImpl;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;
import org.mobicents.protocols.ss7.tcap.api.TCAPStack;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;
import org.mobicents.protocols.ss7.tools.simulator.level1.M3UAManagementProxyImpl;

/**
 * SS7 server used for testing.
 * Remove SCCP, TCAP preview mode and start MAP stack to make the server
 * answering back.
 * 
 * @author Modified by Martin Kacer,
 *         original author amit bhayani in jSS7 SctpClient.java example
 */
public class SS7Server extends AbstractSctpBase
        implements MAPDialogListener, MAPServiceSupplementaryListener, ManagementEventListener, MAPServiceSmsListener {

    private static Logger logger = Logger.getLogger(SS7Server.class);

    // SCTP
    private ManagementImpl sctpManagement;

    // M3UA
    private M3UAManagementImpl serverM3UAMgmt;

    // SCCP
    private SccpStackImpl sccpStack;
    private SccpResourceImpl sccpResource;
    private SccpProvider sccpProvider;

    // TCAP
    private TCAPStack tcapStack;

    // MAP
    private MAPStackImpl mapStack;
    private MAPProvider mapProvider;

    static final private String persistDir = "XmlSctpServer";

    private void initSCTP(IpChannelType ipChannelType) throws Exception {
        logger.debug("Initializing SCTP Stack ....");
        this.sctpManagement = new ManagementImpl("SctpServerSCTP");

        this.sctpManagement.setPersistDir(persistDir);

        this.sctpManagement.setSingleThread(false);
        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        this.sctpManagement.setMaxIOErrors(30);
        this.sctpManagement.removeAllResourses();
        this.sctpManagement.addManagementEventListener(this);

        // 1. Create SCTP Server
        sctpManagement.addServer(SERVER_NAME, SERVER_IP, SERVER_PORT, ipChannelType, null);

        // 2. Create SCTP Server Association
        sctpManagement.addServerAssociation(CLIENT_IP, CLIENT_PORT/* CLIENT_PORT */, SERVER_NAME,
                SERVER_ASSOCIATION_NAME,
                ipChannelType);

        // 3. Start Server
        sctpManagement.startServer(SERVER_NAME);

        logger.debug("Initialized SCTP Stack ....");
    }

    private void initM3UA() throws Exception {
        logger.debug("Initializing M3UA Stack ....");
        this.serverM3UAMgmt = new M3UAManagementProxyImpl("SctpServerM3UA");

        this.serverM3UAMgmt.setPersistDir(persistDir);

        this.serverM3UAMgmt.setTransportManagement(this.sctpManagement);

        this.serverM3UAMgmt.start();
        this.serverM3UAMgmt.removeAllResourses();

        // Step 1 : Create App Server
        RoutingContext rc = factory.createRoutingContext(new long[] { 100l });
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
        this.serverM3UAMgmt.createAs("RAS1", Functionality.SGW, ExchangeType.SE, IPSPType.CLIENT, rc, trafficModeType,
                1, null);

        // Step 2 : Create ASP
        this.serverM3UAMgmt.createAspFactory("RASP1", SERVER_ASSOCIATION_NAME);

        // Step3 : Assign ASP to AS
        AspImpl asp = this.serverM3UAMgmt.assignAspToAs("RAS1", "RASP1");

        // Step 4: Add Route. Remote point code is 1
        this.serverM3UAMgmt.addRoute(CLIENT_SPC, -1, -1, "RAS1");
        // this.serverM3UAMgmt.addRoute(SERVER_SPC, -1, -1, "RAS1");
        logger.debug("Initialized M3UA Stack ....");
    }

    private void initSCCP() throws Exception {
        logger.debug("Initializing SCCP Stack ....");

        // Initialize SCCP stack
        this.sccpStack = new SccpStackImpl("SctpServerSCCP");
        this.sccpStack.setMtp3UserPart(1, this.serverM3UAMgmt);
        this.sccpStack.setPersistDir(persistDir);

        // Start SCCP stack and initialize provider
        this.sccpStack.start();
        this.sccpStack.removeAllResourses();
        this.sccpProvider = this.sccpStack.getSccpProvider();
        logger.debug("SCCP Provider initialized.");

        // Add remote SPC and SSN
        this.sccpStack.getSccpResource().addRemoteSpc(0, CLIENT_SPC, 0, 0);
        this.sccpStack.getSccpResource().addRemoteSsn(0, CLIENT_SPC, SSN, 0, false);
        logger.debug(String.format("Configured Remote SPC: %d and SSN: %d", CLIENT_SPC, SSN));

        // Add MTP3 service access point and destination
        this.sccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, SERVER_SPC, NETWORK_INDICATOR, 0);
        this.sccpStack.getRouter().addMtp3Destination(1, 1, CLIENT_SPC, CLIENT_SPC, 0, 255, 255);
        logger.debug("Added MTP3 Service Access Point and Destination.");

        // Configure routing addresses
        GlobalTitle gtClient = this.sccpProvider.getParameterFactory().createGlobalTitle(
                "*", 0,
                org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,
                null, NatureOfAddress.INTERNATIONAL);

        GlobalTitle gtServer = this.sccpProvider.getParameterFactory().createGlobalTitle(
                "*", 0,
                org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,
                null, NatureOfAddress.INTERNATIONAL);

        this.sccpStack.getRouter().addRoutingAddress(1,
                this.sccpProvider.getParameterFactory().createSccpAddress(
                        RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtClient, CLIENT_SPC, SSN));

        this.sccpStack.getRouter().addRoutingAddress(2,
                this.sccpProvider.getParameterFactory().createSccpAddress(
                        RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtServer, SERVER_SPC, SSN));
        logger.debug("Added Routing Addresses for Client and Server.");

        // Add SCCP Rules
        SccpAddress patternClient = this.sccpProvider.getParameterFactory().createSccpAddress(
                RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtClient, 0, 0);

        SccpAddress patternServer = this.sccpProvider.getParameterFactory().createSccpAddress(
                RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtServer, 0, 0);

        this.sccpStack.getRouter().addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0,
                OriginationType.LOCAL, patternClient, "K", 1, -1, null, 0, null);

        this.sccpStack.getRouter().addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0,
                OriginationType.REMOTE, patternServer, "K", 2, -1, null, 0, null);

        logger.debug("Added SCCP Routing Rules.");
        logger.debug("Initialized SCCP Stack ....");
    }

    private void initMAP() throws Exception {
        logger.debug("Initializing MAP Stack ....");
        this.mapStack = new MAPStackImpl("SctpServerMAP", this.sccpStack.getSccpProvider(), SSN);

        this.tcapStack = this.mapStack.getTCAPStack();

        // this.tcapStack.setPreviewMode(true);
        this.tcapStack.start();
        this.tcapStack.setDialogIdleTimeout(120000); // 120 seconds
        this.tcapStack.setInvokeTimeout(60000);
        this.tcapStack.setMaxDialogs(65535);

        this.mapProvider = this.mapStack.getMAPProvider();

        this.mapProvider.addMAPDialogListener(this);
        this.mapProvider.getMAPServiceSupplementary().addMAPServiceListener(this);
        this.mapProvider.getMAPServiceSms().addMAPServiceListener(this);

        this.mapProvider.getMAPServiceSupplementary().acivate();
        this.mapProvider.getMAPServiceMobility().acivate();

        // Ensure MAPServiceSms is activated
        this.mapProvider.getMAPServiceSms().acivate();

        this.mapStack.start();

        logger.debug("Initialized MAP Stack ....");
    }

    protected void initializeStack(IpChannelType ipChannelType) throws Exception {

        this.initSCTP(ipChannelType);

        // Initialize M3UA first
        this.initM3UA();

        // Initialize SCCP
        this.initSCCP();

        // Initialize MAP
        this.initMAP();

        // 7. Start ASP
        serverM3UAMgmt.startAsp("RASP1");

        logger.debug("[[[[[[[[[[    Started SctpServer       ]]]]]]]]]]");
    }

    protected void releaseStack() {
        this.mapStack.stop();
        this.tcapStack.stop();
        try {
            this.serverM3UAMgmt.stop();
            this.sctpManagement.stop();
        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(SS7Server.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogAccept(
     * org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogAccept(MAPDialog mapDialog, MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogAccept for DialogId=%d MAPExtensionContainer=%s",
                    mapDialog.getLocalDialogId(), extensionContainer));
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogClose(org
     * .mobicents.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogClose(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogClose for Dialog=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogDelimiter
     * (org.mobicents.protocols.ss7.map.api.MAPDialog)
     */
    /*
     * public void onDialogDelimiter(MAPDialog mapDialog) {
     * if (logger.isDebugEnabled()) {
     * logger.debug(String.format("onDialogDelimiter for DialogId=%d",
     * mapDialog.getLocalDialogId()));
     * }
     * }
     */

    // @Override
    @Override
    public void onDialogDelimiter(MAPDialog mapDialog) {
        // This will initiate the TC-END with ReturnResultLast component
        try {
            mapDialog.send();
        } catch (MAPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        /*
         * try {
         * mapDialog.close(false);
         * } catch (MAPException ex) {
         * java.util.logging.Logger.getLogger(SS7Server.class.getName()).log(Level.
         * SEVERE, null, ex);
         * }
         */

        /*
         * USSDString ussdStrObj;
         * try {
         * ussdStrObj = this.mapProvider.getMAPParameterFactory().
         * createUSSDString("Your balance is 500");
         * 
         * CBSDataCodingScheme ussdDataCodingScheme = new CBSDataCodingSchemeImpl(0x0f);
         * ((MAPDialogSupplementary) mapDialog).addProcessUnstructuredSSResponse(
         * this.processUnstructuredSSRequestInvokeId, ussdDataCodingScheme, ussdStrObj);
         * 
         * mapDialog.close(false);
         * } catch (MAPException ex) {
         * java.util.logging.Logger.getLogger(SS7Server.class.getName()).log(Level.
         * SEVERE, null, ex);
         * }
         */
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogNotice(
     * org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic)
     */
    @Override
    public void onDialogNotice(MAPDialog mapDialog, MAPNoticeProblemDiagnostic noticeProblemDiagnostic) {
        logger.error(String.format("onDialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s ",
                mapDialog.getLocalDialogId(), noticeProblemDiagnostic));
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogProviderAbort
     * (org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.dialog.MAPAbortProviderReason,
     * org.mobicents.protocols.ss7.map.api.dialog.MAPAbortSource,
     * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason,
            MAPAbortSource abortSource, MAPExtensionContainer extensionContainer) {
        logger.error(String
                .format("onDialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s",
                        mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer));
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogReject(
     * org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.dialog.MAPRefuseReason,
     * org.mobicents.protocols.ss7.map.api.dialog.MAPProviderError,
     * org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName,
     * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason,
            ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {
        logger.error(String
                .format("onDialogReject for DialogId=%d MAPRefuseReason=%s MAPProviderError=%s ApplicationContextName=%s MAPExtensionContainer=%s",
                        mapDialog.getLocalDialogId(), refuseReason, alternativeApplicationContext,
                        extensionContainer));
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRelease
     * (org.mobicents.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogRelease(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogResease for DialogId=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRequest
     * (org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
     * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
     * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
            MAPExtensionContainer extensionContainer) {
        System.out
                .println("\n\n\n\n\n\n\n\n\n[[[[[[[[[[    onDialogRequest      ]]]]]]]]]]");
        System.out
                .println(String.format(
                        "Dialog Parameters:\n\tDialogId=%d \n\tDestRef=%s \n\tOrigRef=%s\n",
                        mapDialog.getLocalDialogId(), destReference, origReference));
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRequestEricsson
     */
    @Override
    public void onDialogRequestEricsson(MAPDialog mapd, AddressString as, AddressString as1, AddressString as2,
            AddressString as3) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s ",
                    mapd.getLocalDialogId(), as, as1, as2, as3));
        }

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogTimeout
     * (org.mobicents.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogTimeout(MAPDialog mapDialog) {
        logger.error(String.format("onDialogTimeout for DialogId=%d", mapDialog.getLocalDialogId()));
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogUserAbort
     * (org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice,
     * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason,
            MAPExtensionContainer extensionContainer) {
        logger.error(String.format("onDialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s",
                mapDialog.getLocalDialogId(), userReason, extensionContainer));
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onProcessUnstructuredSSRequest(org.mobicents
     * .protocols.ss7.map.api.service
     * .supplementary.ProcessUnstructuredSSRequest)
     */
    @Override
    public void onProcessUnstructuredSSRequest(ProcessUnstructuredSSRequest procUnstrReqInd) {
        logger.debug("[[[[[[[[[[    ProcessUnstructuredSSRequest      ]]]]]]]]]]");

        /*
         * if (1 == 1) {
         * return;
         * }
         */

        if (logger.isDebugEnabled()) {
            try {
                logger.debug(String.format("onProcessUnstructuredSSRequestIndication for DialogId=%d. Ussd String=%s",
                        procUnstrReqInd.getMAPDialog().getLocalDialogId(),
                        procUnstrReqInd.getUSSDString().getString(null)));
            } catch (MAPException ex) {
                java.util.logging.Logger.getLogger(SS7Server.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        try {

            long invokeId = procUnstrReqInd.getInvokeId();
            MAPDialogSupplementary dialog = procUnstrReqInd.getMAPDialog();

            /*
             * ReturnResultLast rrl = ((MAPProviderImpl)
             * dialog.getService().getMAPProvider()).getTCAPProvider()
             * .getComponentPrimitiveFactory().createTCResultLastRequest();
             * rrl.setInvokeId(invokeId);
             * OperationCode opCode = new OperationCodeImpl();
             * opCode.setLocalOperationCode((long)
             * MAPOperationCode.processUnstructuredSS_Request);
             * rrl.setOperationCode(opCode);
             * Parameter par = ((MAPProviderImpl)
             * dialog.getService().getMAPProvider()).getTCAPProvider()
             * .getComponentPrimitiveFactory().createParameter();
             * par.setData(new byte[] { 1, 1, 1, 1, 1 });
             * rrl.setParameter(par);
             * dialog.sendReturnResultLastComponent(rrl);
             */

            // dialog.setUserObject(procUnstrReqInd.getMAPDialog().getUserObject());

            ISDNAddressString msisdn = this.mapProvider.getMAPParameterFactory().createISDNAddressString(
                    AddressNature.international_number, NumberingPlan.ISDN, "11111111111");

            // dialog.setUserObject(invokeId);

            /*
             * MAPDialogSupplementary mapDialog = procUnstrReqInd.getMAPDialog();
             * MAPErrorMessage msg = this.mapProvider.getMAPErrorMessageFactory().
             * createMAPErrorMessageSystemFailure(2, null, null, null);
             * mapDialog.sendErrorComponent(procUnstrReqInd.getInvokeId(), msg);
             */

            USSDString ussdStrObj = this.mapProvider.getMAPParameterFactory().createUSSDString(
                    "USSD String : ......................................");
            CBSDataCodingSchemeImpl ussdDataCodingScheme = new CBSDataCodingSchemeImpl(0x0F);
            dialog.addProcessUnstructuredSSResponse(invokeId, ussdDataCodingScheme, ussdStrObj);

            /*
             * GlobalTitle callingGT =
             * this.sccpProvider.getParameterFactory().createGlobalTitle("222222222222", 0,
             * org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
             * NatureOfAddress.INTERNATIONAL);
             * GlobalTitle calledGT =
             * this.sccpProvider.getParameterFactory().createGlobalTitle("111111111111", 0,
             * org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
             * NatureOfAddress.INTERNATIONAL);
             * SccpAddress callingParty =
             * this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
             * RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, callingGT, 1, 8);
             * SccpAddress calledParty =
             * this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
             * RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledGT, 2, 8);
             * MAPDialogSupplementary mapDialog =
             * this.mapProvider.getMAPServiceSupplementary().createNewDialog(
             * MAPApplicationContext.getInstance(MAPApplicationContextName.
             * networkUnstructuredSsContext,
             * MAPApplicationContextVersion.version2), callingParty,
             * dialog.getReceivedDestReference(), calledParty,
             * dialog.getReceivedOrigReference());
             * 
             * mapDialog.addProcessUnstructuredSSRequest(ussdDataCodingScheme, ussdStrObj,
             * null, msisdn);
             */
            // dialog.addProcessUnstructuredSSRequest(ussdDataCodingScheme, ussdStrObj,
            // null, msisdn);

            // MAPErrorMessage msg =
            // this.mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageSystemFailure(2,
            // null, null, null);
            // mapDialog.sendErrorComponent(procUnstrReqInd.getInvokeId(), msg);
            // mapDialog.send();

            // dialog.sendReturnResultLastComponent(returnResultLast);

            // dialog.send();

            // dialog.close(false);

            // initiateUSSD();

            // dialog.closeDelayed(false);

            /*
             * logger.
             * debug("[[[[[[[[[[    Sending ProcessUnstructuredSSResponse      ]]]]]]]]]]");
             * logger.debug(" dialog = " + dialog.toString());
             * logger.debug(" getLocalAddress = " + dialog.getLocalAddress().toString());
             * logger.debug(" getRemoteAddress = " + dialog.getRemoteAddress().toString());
             * logger.debug(" getState = " + dialog.getState().toString());
             * logger.debug(" invokeid = " + procUnstrReqInd.getInvokeId());
             */
            // MAPErrorMessage mapErrorMessage = null;
            // mapErrorMessage =
            // mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageSystemFailure(
            // (long)
            // dialog.getApplicationContext().getApplicationContextVersion().getVersion(),
            // NetworkResource.hlr, null, null);
            // dialog.sendErrorComponent(invokeId, mapErrorMessage);

            // dialog.close(false);

            // dialog.send();
            // MAPErrorMessage m =
            // mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageAbsentSubscriber(Boolean.FALSE);
            // dialog.sendErrorComponent(invokeId, m);

        } catch (MAPException e) {
            logger.error("Error while sending UnstructuredSSRequest ", e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onProcessUnstructuredSSResponse(org.mobicents
     * .protocols.ss7.map.api.service
     * .supplementary.ProcessUnstructuredSSResponse)
     */
    @Override
    public void onProcessUnstructuredSSResponse(ProcessUnstructuredSSResponse procUnstrResInd) {
        logger.debug("[[[[[[[[[[    onUnstructuredSSNotifyRequest      ]]]]]]]]]]");
        /*
         * // Server shouldn't be getting ProcessUnstructuredSSResponseIndication
         * logger.error(String.
         * format("onProcessUnstructuredSSResponseIndication for Dialog=%d and invokeId=%d"
         * ,
         * procUnstrResInd.getMAPDialog().getLocalDialogId(),
         * procUnstrResInd.getInvokeId()));
         */
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onUnstructuredSSNotifyRequest(org.mobicents
     * .protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyRequest)
     */
    @Override
    public void onUnstructuredSSNotifyRequest(UnstructuredSSNotifyRequest unstrNotifyInd) {
        logger.debug("[[[[[[[[[[    onUnstructuredSSNotifyRequest      ]]]]]]]]]]");
        /*
         * // This error condition. Client should never receive the
         * // UnstructuredSSNotifyRequestIndication
         * logger.error(String.
         * format("onUnstructuredSSNotifyRequest for Dialog=%d and invokeId=%d",
         * unstrNotifyInd
         * .getMAPDialog().getLocalDialogId(), unstrNotifyInd.getInvokeId()));
         */
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onUnstructuredSSNotifyResponse(org.mobicents
     * .protocols.ss7.map.api.service
     * .supplementary.UnstructuredSSNotifyResponse)
     */
    @Override
    public void onUnstructuredSSNotifyResponse(UnstructuredSSNotifyResponse unstrNotifyInd) {
        logger.debug("[[[[[[[[[[    onUnstructuredSSNotifyResponse      ]]]]]]]]]]");
        /*
         * // This error condition. Client should never receive the
         * // UnstructuredSSNotifyRequestIndication
         * logger.error(String.
         * format("onUnstructuredSSNotifyResponse for Dialog=%d and invokeId=%d",
         * unstrNotifyInd
         * .getMAPDialog().getLocalDialogId(), unstrNotifyInd.getInvokeId()));
         */
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onUnstructuredSSRequest(org.mobicents.protocols
     * .ss7.map.api.service.supplementary.UnstructuredSSRequest)
     */
    @Override
    public void onUnstructuredSSRequest(UnstructuredSSRequest unstrReqInd) {
        logger.debug("[[[[[[[[[[    onUnstructuredSSRequest      ]]]]]]]]]]");
        /*
         * // Server shouldn't be getting UnstructuredSSRequestIndication
         * logger.error(String.
         * format("onUnstructuredSSRequestIndication for Dialog=%d and invokeId=%d",
         * unstrReqInd
         * .getMAPDialog().getLocalDialogId(), unstrReqInd.getInvokeId()));
         */
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onUnstructuredSSResponse(org.mobicents.protocols
     * .ss7.map.api.service.supplementary.UnstructuredSSResponse)
     */
    @Override
    public void onUnstructuredSSResponse(UnstructuredSSResponse unstrResInd) {
        logger.debug("[[[[[[[[[[    onUnstructuredSSResponse      ]]]]]]]]]]");
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onErrorComponent
     * (org.mobicents.protocols.ss7.map.api.MAPDialog, java.lang.Long,
     * org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage)
     */
    @Override
    public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
        logger.error(String.format("onErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage=%s",
                mapDialog.getLocalDialogId(), invokeId, mapErrorMessage));
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onInvokeTimeout
     * (org.mobicents.protocols.ss7.map.api.MAPDialog, java.lang.Long)
     */
    @Override
    public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
        logger.error(
                String.format("onInvokeTimeout for Dialog=%d and invokeId=%d", mapDialog.getLocalDialogId(), invokeId));
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onMAPMessage(org
     * .mobicents.protocols.ss7.map.api.MAPMessage)
     */
    @Override
    public void onMAPMessage(MAPMessage arg0) {
        // TODO Auto-generated method stub
        System.out.println("[[[[[[[[[[    onMAPMessage      ]]]]]]]]]]");
    }

    /**
     * @param args
     */
    public static void main(String[] args) {
        logger.debug("*************************************");
        logger.debug("***           SS7Server           ***");
        logger.debug("*************************************");

        // clear XML dir
        File index = new File(persistDir);
        if (!index.exists()) {
            index.mkdir();
        } else {
            String[] entries = index.list();
            for (String s : entries) {
                File currentFile = new File(index.getPath(), s);
                currentFile.delete();
            }
        }
        //

        IpChannelType ipChannelType = IpChannelType.SCTP;
        if (args.length >= 1 && args[0].toLowerCase().equals("tcp")) {
            ipChannelType = IpChannelType.TCP;
        }

        logger.setLevel(org.apache.log4j.Level.DEBUG);

        final SS7Server server = new SS7Server();
        try {
            server.initializeStack(ipChannelType);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // int counter = 0;

        try {
            while (true) {
                if (server.serverM3UAMgmt.isStarted() == true) {
                    for (As a : server.serverM3UAMgmt.getAppServers()) {
                        if (a.isConnected() && a.isUp()) {
                            // server.initiateUSSD();
                            // if (counter == 0) {
                            // server.initiateSendRoutingInfo();
                            // counter++;
                            // }
                        }
                    }

                } else {
                    // server.serverM3UAMgmt.start();
                }

                Thread.sleep(1000);
            }
        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(SS7Server.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    @Override
    public void onRegisterSSRequest(RegisterSSRequest request) {
        logger.debug("[[[[[[[[[[    onRegisterSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onRegisterSSResponse(RegisterSSResponse response) {
        logger.debug("[[[[[[[[[[    onRegisterSSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onEraseSSRequest(EraseSSRequest request) {
        logger.debug("[[[[[[[[[[    onEraseSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onEraseSSResponse(EraseSSResponse response) {
        logger.debug("[[[[[[[[[[    onEraseSSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onActivateSSRequest(ActivateSSRequest request) {
        logger.debug("[[[[[[[[[[    onActivateSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onActivateSSResponse(ActivateSSResponse response) {
        logger.debug("[[[[[[[[[[    onActivateSSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onDeactivateSSRequest(DeactivateSSRequest request) {
        logger.debug("[[[[[[[[[[    onDeactivateSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onDeactivateSSResponse(DeactivateSSResponse response) {
        logger.debug("[[[[[[[[[[    onDeactivateSSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onInterrogateSSRequest(InterrogateSSRequest request) {
        logger.debug("[[[[[[[[[[    onInterrogateSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onInterrogateSSResponse(InterrogateSSResponse response) {
        logger.debug("[[[[[[[[[[    onInterrogateSSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onGetPasswordRequest(GetPasswordRequest request) {
        logger.debug("[[[[[[[[[[    onGetPasswordRequest      ]]]]]]]]]]");
    }

    @Override
    public void onGetPasswordResponse(GetPasswordResponse response) {
        logger.debug("[[[[[[[[[[    onGetPasswordResponse      ]]]]]]]]]]");
    }

    @Override
    public void onRegisterPasswordRequest(RegisterPasswordRequest request) {
        logger.debug("[[[[[[[[[[    onRegisterPasswordRequest      ]]]]]]]]]]");
    }

    @Override
    public void onRegisterPasswordResponse(RegisterPasswordResponse response) {
        logger.debug("[[[[[[[[[[    onRegisterPasswordResponse      ]]]]]]]]]]");
    }

    @Override
    public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem, boolean isLocalOriginated) {
        logger.debug("[[[[[[[[[[    onRejectComponent      ]]]]]]]]]]");
    }

    @Override
    public void onAlertServiceCentreRequest(AlertServiceCentreRequest request) {
        logger.debug("Received AlertServiceCentreRequest: " + request);
    }

    @Override
    public void onMoForwardShortMessageResponse(MoForwardShortMessageResponse response) {
        logger.debug("Received MoForwardShortMessageResponse: " + response);
    }

    @Override
    public void onMtForwardShortMessageResponse(MtForwardShortMessageResponse response) {
        logger.debug("Received MtForwardShortMessageResponse: " + response);
    }

    @Override
    public void onMoForwardShortMessageRequest(MoForwardShortMessageRequest request) {
        logger.debug("Received MoForwardShortMessageRequest: " + request);
    }

    @Override
    public void onReadyForSMRequest(ReadyForSMRequest request) {
        logger.debug("Received ReadyForSMRequest: " + request);
    }

    @Override
    public void onReportSMDeliveryStatusResponse(ReportSMDeliveryStatusResponse response) {
        logger.debug("Received ReportSMDeliveryStatusResponse: " + response);
    }

    @Override
    public void onForwardShortMessageRequest(ForwardShortMessageRequest request) {
        logger.debug("Received ForwardShortMessageRequest: " + request);
    }

    @Override
    public void onForwardShortMessageResponse(ForwardShortMessageResponse response) {
        logger.debug("Received ForwardShortMessageResponse: " + response);
    }

    @Override
    public void onAlertServiceCentreResponse(AlertServiceCentreResponse response) {
        logger.debug("Received AlertServiceCentreResponse: " + response);
    }

    @Override
    public void onReportSMDeliveryStatusRequest(ReportSMDeliveryStatusRequest request) {
        logger.debug("Received ReportSMDeliveryStatusRequest: " + request);
    }

    @Override
    public void onNoteSubscriberPresentRequest(NoteSubscriberPresentRequest request) {
        logger.debug("Received NoteSubscriberPresentRequest: " + request);
    }

    @Override
    public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest request) {
        logger.debug("Received MtForwardShortMessageRequest: " + request);
    }

    @Override
    public void onInformServiceCentreRequest(InformServiceCentreRequest request) {
        logger.debug("Received InformServiceCentreRequest: " + request);
    }

    @Override
    public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse response) {
        logger.debug("Received SendRoutingInfoForSMResponse: " + response);
    }

    @Override
    public void onReadyForSMResponse(ReadyForSMResponse response) {
        logger.debug("Received ReadyForSMResponse: " + response);
    }

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest request) {
        System.out.println("[[[[[[[[[[    onSendRoutingInfoForSMRequest      ]]]]]]]]]]");
        System.out
                .println("\n>>>>>>>>>>>>>>>>> Received SendRoutingInfoForSMRequest from SS7 Client <<<<<<<<<<<<<<<<<");
        MAPDialogSms mapDialog = request.getMAPDialog();

        try {
            String msisdn = request.getMsisdn().getAddress();

            long invokeId = request.getInvokeId();
            IMSI imsi = request.getImsi();
            String imsiString = imsi.getData();
            AddressString serviceCenterAddress = request.getServiceCentreAddress();

            System.out.println("Parameters: \n\tIMSI: " + imsiString + "\n\tMSISDN: " + msisdn
                    + "\n\tService Center Address: \n\t\tNature: " + serviceCenterAddress.getAddressNature() +
                    "\n\t\tPlan: " + serviceCenterAddress.getNumberingPlan() + "\n\t\tAddress: "
                    + serviceCenterAddress.getAddress());

            // ====================================================================================

            String serviceCenterAddressJson = String.format(
                    "{\"addressNature\": \"%s\", \"numberingPlan\": \"%s\", \"address\": \"%s\"}",
                    serviceCenterAddress.getAddressNature(),
                    serviceCenterAddress.getNumberingPlan(),
                    serviceCenterAddress.getAddress());

            try (BufferedWriter writer = new BufferedWriter(new FileWriter("/tmp/routing_info_req_pipe"))) {
                String message = String.format(
                        "{\"imsi\": \"%s\", \"msisdn\": \"%s\", \"serviceCenterAddress\": %s}",
                        imsiString,
                        msisdn,
                        serviceCenterAddressJson);
                writer.write(message);
                writer.newLine();
                writer.flush();
                System.out
                        .println(
                                "\n>>>>>>>>>>>>>>>>> Sent Request to Diameter Client <<<<<<<<<<<<<<<<<");
            } catch (Exception e) {
                e.printStackTrace();
            }

            String mscNumberString = null;

            try (BufferedReader reader = new BufferedReader(new FileReader("/tmp/routing_info_res_pipe"))) {
                String message;
                while ((message = reader.readLine()) != null) {
                    System.out
                            .println(
                                    "\n>>>>>>>>>>>>>>>>> Received Response from Diameter Client <<<<<<<<<<<<<<<<<");

                    JSONParser parser = new JSONParser();
                    JSONObject jsonObject = (JSONObject) parser.parse(message);

                    imsiString = (String) jsonObject.get("username");
                    mscNumberString = (String) jsonObject.get("mscNumber");
                    msisdn = (String) jsonObject.get("msisdn");
                    System.out.println("\nReceived Parameters: \n\tIMSI: " + imsiString + "\n\tMSISDN: " + msisdn
                            + "\n\tMSC Number: " + mscNumberString);
                }
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("SS7 Server: Failed to read from the pipe.");
            } catch (ParseException e) {
                e.printStackTrace();
            }

            // ====================================================================================

            ISDNAddressString mscNumber = mapProvider.getMAPParameterFactory().createISDNAddressString(
                    AddressNature.international_number,
                    NumberingPlan.ISDN,
                    mscNumberString);
            LMSI lmsi = null;
            boolean gprsNodeIndicator = false;
            AdditionalNumber additionalNumber = null;
            MAPExtensionContainer extensionContainer = request.getExtensionContainer();
            LocationInfoWithLMSI locationInfoWithLMSI = mapProvider.getMAPParameterFactory()
                    .createLocationInfoWithLMSI(mscNumber, lmsi, extensionContainer, gprsNodeIndicator,
                            additionalNumber);

            mapDialog.addSendRoutingInfoForSMResponse(invokeId, imsi, locationInfoWithLMSI,
                    extensionContainer, null,
                    null);
            System.out
                    .println(
                            "\n>>>>>>>>>>>>>>>>> SendRoutingInfoForSMResponse sent to SS7 Client <<<<<<<<<<<<<<<<<");
        } catch (Exception e) {
            logger.error("Error processing SendRoutingInfoForSMRequest", e);
        }
    }

    private void initiateUSSD() throws MAPException {
        logger.debug("[[[[[[[[[[    initiateUSSD      ]]]]]]]]]]");

        // SccpAddress callingParty =
        // this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
        // null, 1, SSN);
        // SccpAddress calledParty =
        // this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
        // null, 2, SSN);

        GlobalTitle callingGT = this.sccpProvider.getParameterFactory().createGlobalTitle("111111111111", 0,
                org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                NatureOfAddress.INTERNATIONAL);
        GlobalTitle calledGT = this.sccpProvider.getParameterFactory().createGlobalTitle("222222222222", 0,
                org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                NatureOfAddress.INTERNATIONAL);

        SccpAddress callingParty = this.sccpStack.getSccpProvider().getParameterFactory()
                .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, callingGT, SERVER_SPC, 8);
        SccpAddress calledParty = this.sccpStack.getSccpProvider().getParameterFactory()
                .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledGT, CLIENT_SPC, 8);

        ISDNAddressString origReference = this.mapProvider.getMAPParameterFactory()
                .createISDNAddressString(AddressNature.international_number, NumberingPlan.land_mobile, "11111111111");
        ISDNAddressString destReference = this.mapProvider.getMAPParameterFactory().createISDNAddressString(
                AddressNature.international_number, NumberingPlan.land_mobile, "111111111111111");

        // First create Dialog
        MAPDialogSupplementary mapDialog = this.mapProvider.getMAPServiceSupplementary().createNewDialog(
                MAPApplicationContext.getInstance(MAPApplicationContextName.networkUnstructuredSsContext,
                        MAPApplicationContextVersion.version2),
                callingParty, origReference, calledParty, destReference);

        CBSDataCodingSchemeImpl ussdDataCodingScheme = new CBSDataCodingSchemeImpl(0x0F);

        // USSD String: *111*+11111111111#
        // The Charset is null, here we let system use default Charset (UTF-7 as
        // explained in GSM 03.38. However if MAP User wants, it can set its own
        // impl of Charset
        USSDString ussdString = this.mapProvider.getMAPParameterFactory().createUSSDString("*111*+11111111111#",
                ussdDataCodingScheme, null);

        ISDNAddressString msisdn = this.mapProvider.getMAPParameterFactory().createISDNAddressString(
                AddressNature.international_number, NumberingPlan.ISDN, "11111111111");

        mapDialog.addProcessUnstructuredSSRequest(ussdDataCodingScheme, ussdString, null, msisdn);

        // This will initiate the TC-BEGIN with INVOKE component
        mapDialog.send();
    }

    public void onServiceStarted() {
        logger.debug("[[[[[[[[[[    onServiceStarted      ]]]]]]]]]]");
    }

    public void onServiceStopped() {
        logger.debug("[[[[[[[[[[    onServiceStopped      ]]]]]]]]]]");
    }

    public void onRemoveAllResources() {
        logger.debug("[[[[[[[[[[    onRemoveAllResources      ]]]]]]]]]]");
    }

    public void onServerAdded(Server server) {
        logger.debug("[[[[[[[[[[    onServerAdded      ]]]]]]]]]]");
    }

    public void onServerRemoved(Server server) {
        logger.debug("[[[[[[[[[[    onServerRemoved      ]]]]]]]]]]");
    }

    public void onAssociationAdded(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationAdded      ]]]]]]]]]]");
    }

    public void onAssociationRemoved(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationRemoved      ]]]]]]]]]]");
    }

    public void onAssociationStarted(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationStarted      ]]]]]]]]]]");
    }

    public void onAssociationStopped(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationStopped      ]]]]]]]]]]");
    }

    public void onAssociationUp(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationUp      ]]]]]]]]]]");
        if (asctn != null) {
            logger.warn(String.format("SCTP AssociationUp name=%s peer=%s", asctn.getName(), asctn.getPeerAddress()));
        }
    }

    public void onAssociationDown(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationDown      ]]]]]]]]]]");
        if (asctn != null) {
            logger.warn(String.format("SCTP AssociationDown name=%s peer=%s", asctn.getName(), asctn.getPeerAddress()));
        }
    }

}
