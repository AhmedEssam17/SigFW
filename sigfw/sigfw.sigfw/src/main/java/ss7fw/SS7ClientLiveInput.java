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
 * Modified jSS7 SctpClient.java example
 * Read raw SCCP packet from Json file and forward them over M3UA link
 */
package ss7fw;

import java.io.File;
import java.io.RandomAccessFile;
import java.util.Random;
import org.apache.log4j.Logger;
import org.mobicents.protocols.api.Association;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.api.ManagementEventListener;
import org.mobicents.protocols.api.Server;
import org.mobicents.protocols.sctp.ManagementImpl;
import org.mobicents.protocols.ss7.indicator.NatureOfAddress;
import org.mobicents.protocols.ss7.indicator.RoutingIndicator;
import org.mobicents.protocols.ss7.isup.message.parameter.CorrelationID;
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
import org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan;
import org.mobicents.protocols.ss7.map.api.primitives.USSDString;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.TeleserviceCode;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
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
import org.mobicents.protocols.ss7.map.api.service.sms.SMDeliveryNotIntended;
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_DA;
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_MTI;
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_OA;
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_SMEA;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.SmsSignalInfo;
import org.mobicents.protocols.ss7.map.api.service.supplementary.MAPDialogSupplementary;
import org.mobicents.protocols.ss7.map.datacoding.CBSDataCodingSchemeImpl;
import org.mobicents.protocols.ss7.mtp.Mtp3TransferPrimitive;
import org.mobicents.protocols.ss7.sccp.LoadSharingAlgorithm;
import org.mobicents.protocols.ss7.sccp.OriginationType;
import org.mobicents.protocols.ss7.sccp.RuleType;
import org.mobicents.protocols.ss7.sccp.SccpProvider;
import org.mobicents.protocols.ss7.sccp.impl.SccpStackImpl;
import org.mobicents.protocols.ss7.sccp.impl.router.RouterImpl;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;
import org.mobicents.protocols.ss7.tcap.api.TCAPStack;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName;
import org.mobicents.protocols.ss7.tools.simulator.level1.M3UAManagementProxyImpl;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;

/**
 * SS7 client used for testing. The client read from named pipe then input.
 * Required input is json generated by tshark -T ek -x. The sccp_raw is
 * used to forward the SCCP data over M3UA link.
 * 
 * @author Modified by Martin Kacer,
 *         original author amit bhayani in jSS7 SctpClient.java example
 */
public class SS7ClientLiveInput extends AbstractSctpBase
        implements ManagementEventListener, MAPDialogListener, MAPServiceSmsListener {

    private static Logger logger = Logger.getLogger(SS7ClientLiveInput.class);

    // SCTP
    private ManagementImpl sctpManagement;

    // M3UA
    private M3UAManagementImpl clientM3UAMgmt;

    // SCCP
    private SccpStackImpl sccpStack;
    private SccpProvider sccpProvider;

    // TCAP
    private TCAPStack tcapStack;

    // MAP
    private MAPStackImpl mapStack;
    private MAPProvider mapProvider;

    static final private String persistDir = "XmlSctpClientLiveInput";

    static Random randomGenerator = new Random();

    /**
     *
     */
    public SS7ClientLiveInput() {
        // TODO Auto-generated constructor stub
    }

    protected void initializeStack(IpChannelType ipChannelType) throws Exception {

        this.initSCTP(ipChannelType);

        // Initialize M3UA first
        this.initM3UA();

        // Initialize SCCP
        this.initSCCP();

        // Initialize MAP
        this.initMAP();

        // Finally start ASP
        // Set 5: Finally start ASP
        this.clientM3UAMgmt.startAsp("ASP1");

        // wait for M3UA link
        /*
         * boolean m3ua_connected = false;
         * while (this.clientM3UAMgmt.isStarted() == false && m3ua_connected == false) {
         * Thread.sleep(3000);
         * for (As a : this.clientM3UAMgmt.getAppServers()) {
         * if (a.isConnected() && a.isUp()) {
         * m3ua_connected = true;
         * }
         * }
         * this.clientM3UAMgmt.startAsp("ASP1");
         * }
         */

    }

    private void initSCTP(IpChannelType ipChannelType) throws Exception {
        logger.debug("Initializing SCTP Stack ....");
        this.sctpManagement = new ManagementImpl("SctpClientSCTP");

        this.sctpManagement.setPersistDir(persistDir);

        this.sctpManagement.setSingleThread(false);
        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        this.sctpManagement.setMaxIOErrors(30);
        this.sctpManagement.removeAllResourses();
        this.sctpManagement.addManagementEventListener(this);

        // 1. Create SCTP Association
        sctpManagement.addAssociation(CLIENT_IP, CLIENT_PORT, SERVER_IP, /* SERVER_PORT */SERVER_PORT,
                CLIENT_ASSOCIATION_NAME,
                ipChannelType, null);
        logger.debug("Initialized SCTP Stack ....");

    }

    private void initM3UA() throws Exception {
        logger.debug("Initializing M3UA Stack ....");
        this.clientM3UAMgmt = new M3UAManagementProxyImpl("SctpClientLiveInputM3UA");

        this.clientM3UAMgmt.setPersistDir(persistDir);

        this.clientM3UAMgmt.setTransportManagement(this.sctpManagement);
        this.clientM3UAMgmt.start();
        this.clientM3UAMgmt.removeAllResourses();

        // m3ua as create rc <rc> <ras-name>
        RoutingContext rc = factory.createRoutingContext(new long[] { 100l });
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
        this.clientM3UAMgmt.createAs("AS1", Functionality.AS, ExchangeType.SE, IPSPType.CLIENT, rc, trafficModeType, 1,
                null);

        // Step 2 : Create ASP
        this.clientM3UAMgmt.createAspFactory("ASP1", CLIENT_ASSOCIATION_NAME);

        // Step3 : Assign ASP to AS
        AspImpl asp = this.clientM3UAMgmt.assignAspToAs("AS1", "ASP1");

        // Step 4: Add Route. Remote point code is 2
        clientM3UAMgmt.addRoute(SERVER_SPC, -1, -1, "AS1");

        logger.debug("Initialized M3UA Stack ....");

    }

    private void initSCCP() throws Exception {
        logger.debug("Initializing SCCP Stack ....");

        // Initialize SCCP stack
        if (this.clientM3UAMgmt == null) {
            throw new NullPointerException(
                    "M3UA Management (clientM3UAMgmt) is null. Ensure M3UA is initialized before SCCP.");
        }
        this.sccpStack = new SccpStackImpl("SctpClientLiveInputSCCP");
        this.sccpStack.setPersistDir(persistDir);

        // Bind M3UA to SCCP
        this.sccpStack.setMtp3UserPart(1, this.clientM3UAMgmt);

        // Start SCCP Stack
        this.sccpStack.start();
        this.sccpStack.removeAllResourses();

        // Initialize SCCP Provider
        this.sccpProvider = this.sccpStack.getSccpProvider();
        if (this.sccpProvider == null) {
            throw new NullPointerException("SCCP Provider is null. Ensure the SCCP stack is properly started.");
        }
        logger.debug("SCCP Provider initialized.");

        // Add Remote SPC and SSN for Server
        // if (SERVER_SPC == 0 || SSN == 0) {
        // throw new IllegalArgumentException("SERVER_SPC or SSN is not properly
        // configured. Check constants.");
        // }
        this.sccpStack.getSccpResource().addRemoteSpc(0, SERVER_SPC, 0, 0);
        this.sccpStack.getSccpResource().addRemoteSsn(0, SERVER_SPC, SSN, 0, false);
        logger.debug(String.format("Configured Remote SPC: %d and SSN: %d", SERVER_SPC, SSN));

        // Configure MTP3 Service Access Point and Destination
        this.sccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, CLIENT_SPC, NETWORK_INDICATOR, 0);
        this.sccpStack.getRouter().addMtp3Destination(1, 1, SERVER_SPC, SERVER_SPC, 0, 255, 255);

        // Configure Routing Addresses
        GlobalTitle gtClient = this.sccpProvider.getParameterFactory().createGlobalTitle("*", 0,
                org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                NatureOfAddress.INTERNATIONAL);
        GlobalTitle gtServer = this.sccpProvider.getParameterFactory().createGlobalTitle("*", 0,
                org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                NatureOfAddress.INTERNATIONAL);

        this.sccpStack.getRouter().addRoutingAddress(1, this.sccpProvider.getParameterFactory()
                .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtServer, SERVER_SPC, SSN));

        this.sccpStack.getRouter().addRoutingAddress(2, this.sccpProvider.getParameterFactory()
                .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtClient, CLIENT_SPC, SSN));

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
        // this.mapStack = new MAPStackImpl(this.sccpStack.getSccpProvider(),
        // SSN);
        this.mapStack = new MAPStackImpl("SctpClientLiveInputMAP", this.sccpStack.getSccpProvider(), SSN);

        this.tcapStack = this.mapStack.getTCAPStack();
        this.tcapStack.start();
        this.tcapStack.setDialogIdleTimeout(60000);
        this.tcapStack.setInvokeTimeout(30000);
        this.tcapStack.setMaxDialogs(2000);

        this.mapProvider = this.mapStack.getMAPProvider();

        this.mapProvider.addMAPDialogListener(this);
        // this.mapProvider.getMAPServiceSupplementary().addMAPServiceListener(this);

        this.mapProvider.getMAPServiceSupplementary().acivate();
        this.mapProvider.getMAPServiceMobility().acivate();

        // Ensure MAPServiceSms is activated
        this.mapProvider.getMAPServiceSms().addMAPServiceListener(this);
        this.mapProvider.getMAPServiceSms().acivate();

        this.mapStack.start();
        logger.debug("Initialized MAP Stack ....");
    }

    private void initiateUSSD() throws MAPException {

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
                .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, callingGT, CLIENT_SPC, 8);
        SccpAddress calledParty = this.sccpStack.getSccpProvider().getParameterFactory()
                .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledGT, SERVER_SPC, 8);

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

    private void initiateSendRoutingInfo() throws MAPException {
        try {
            // System.out
            // .println("\n\n\n\n\n\n\n\n\n[[[[[[[[[[ Initiate SendRoutingInfo Request
            // ]]]]]]]]]]");

            SccpAddress callingParty = this.sccpProvider.getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                    this.sccpProvider.getParameterFactory().createGlobalTitle("111111111111", 0,
                            org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                            NatureOfAddress.INTERNATIONAL),
                    CLIENT_SPC, 8);

            SccpAddress calledParty = this.sccpProvider.getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                    this.sccpProvider.getParameterFactory().createGlobalTitle("222222222222", 0,
                            org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                            NatureOfAddress.INTERNATIONAL),
                    SERVER_SPC, 8);

            ISDNAddressString clientOrigReference = this.mapProvider.getMAPParameterFactory().createISDNAddressString(
                    AddressNature.international_number, NumberingPlan.land_mobile, "11111111111");
            ISDNAddressString clientDestReference = this.mapProvider.getMAPParameterFactory().createISDNAddressString(
                    AddressNature.international_number, NumberingPlan.land_mobile, "44444444444");

            MAPDialogSms clientDialog = this.mapProvider.getMAPServiceSms().createNewDialog(
                    MAPApplicationContext.getInstance(MAPApplicationContextName.shortMsgGatewayContext,
                            MAPApplicationContextVersion.version2),
                    callingParty, clientOrigReference, calledParty, clientDestReference);

            IMSI imsi = this.mapProvider.getMAPParameterFactory().createIMSI("2222222222");

            clientDialog.addSendRoutingInfoForSMRequest(clientOrigReference, false,
                    clientDestReference, null, false,
                    null, null, null, false, imsi, false, false, null);
            clientDialog.send();
            System.out
                    .println(
                            "\n\n\n\n\n\n\n\n\n\n\n\n[[[[[[[[[[    Initiate SendRoutingInfo Request      ]]]]]]]]]]");

            System.out.println("MAP Dialog Parameters: \n\tIMSI: " + imsi.getData() + "\n\tMSISDN: "
                    + clientOrigReference.getAddress()
                    + "\n\tService Center Address: \n\t\tNature: " + clientDestReference.getAddressNature() +
                    "\n\t\tPlan: " + clientDestReference.getNumberingPlan() + "\n\t\tAddress: "
                    + clientDestReference.getAddress());
            System.out
                    .println(
                            "\n>>>>>>>>>>>>>>>>> MAPDialogSms created and sent to SS7 Server <<<<<<<<<<<<<<<<<");
        } catch (MAPException e) {
            logger.error("Error while initiating Routing Info Request: " +
                    e.getMessage(), e);
        }
    }

    @Override
    public void onAlertServiceCentreRequest(AlertServiceCentreRequest request) {
        logger.info("Received AlertServiceCentreRequest (Client): " + request);
        // Handle the AlertServiceCentreRequest logic here
    }

    @Override
    public void onMoForwardShortMessageResponse(MoForwardShortMessageResponse response) {
        logger.info("Received MoForwardShortMessageResponse (Client): " + response);
        // Process the response here if necessary
    }

    @Override
    public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem, boolean isLocalOriginated) {
        logger.error("RejectComponent received (Client): DialogId=" + mapDialog.getLocalDialogId() +
                ", InvokeId=" + invokeId + ", Problem=" + problem + ", LocalOriginated=" + isLocalOriginated);
        // Additional logic for handling rejection
    }

    @Override
    public void onMtForwardShortMessageResponse(MtForwardShortMessageResponse response) {
        logger.info("Received MtForwardShortMessageResponse (Client): " + response);
        // Process the response here
    }

    @Override
    public void onMoForwardShortMessageRequest(MoForwardShortMessageRequest request) {
        logger.info("Received MoForwardShortMessageRequest (Client): " + request);
        // Handle MO Forward Short Message logic here
    }

    @Override
    public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
        logger.error("Invoke timeout (Client): DialogId=" + mapDialog.getLocalDialogId() + ", InvokeId=" + invokeId);
        // Handle timeout logic here
    }

    @Override
    public void onReadyForSMRequest(ReadyForSMRequest request) {
        logger.info("Received ReadyForSMRequest (Client): " + request);
        // Handle the request here
    }

    @Override
    public void onReportSMDeliveryStatusResponse(ReportSMDeliveryStatusResponse response) {
        logger.info("Received ReportSMDeliveryStatusResponse (Client): " + response);
        // Process the response here
    }

    @Override
    public void onMAPMessage(MAPMessage message) {
        System.out
                .println("\n[[[[[[[[[[    onMAPMessage      ]]]]]]]]]]");
        // Handle MAP messages
    }

    @Override
    public void onForwardShortMessageRequest(ForwardShortMessageRequest request) {
        logger.info("Received ForwardShortMessageRequest (Client): " + request);
        // Handle Forward Short Message logic here
    }

    @Override
    public void onForwardShortMessageResponse(ForwardShortMessageResponse response) {
        logger.info("Received ForwardShortMessageResponse (Client): " + response);
        // Process the response here
    }

    @Override
    public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage errorMessage) {
        logger.error("Error Component received (Client): DialogId=" + mapDialog.getLocalDialogId() +
                ", InvokeId=" + invokeId + ", Error=" + errorMessage);
        // Additional error handling logic here
    }

    @Override
    public void onAlertServiceCentreResponse(AlertServiceCentreResponse response) {
        logger.info("Received AlertServiceCentreResponse (Client): " + response);
        // Process AlertServiceCentreResponse here
    }

    @Override
    public void onReportSMDeliveryStatusRequest(ReportSMDeliveryStatusRequest request) {
        logger.info("Received ReportSMDeliveryStatusRequest (Client): " + request);
        // Handle the request here
    }

    @Override
    public void onNoteSubscriberPresentRequest(NoteSubscriberPresentRequest request) {
        logger.info("Received NoteSubscriberPresentRequest (Client): " + request);
        // Handle NoteSubscriberPresentRequest logic here
    }

    @Override
    public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest request) {
        logger.info("Received MtForwardShortMessageRequest (Client): " + request);
        // Process the MT forward short message request
    }

    @Override
    public void onInformServiceCentreRequest(InformServiceCentreRequest request) {
        logger.info("Received InformServiceCentreRequest (Client): " + request);
        // Handle InformServiceCentreRequest logic
    }

    @Override
    public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse response) {
        System.out.println("[[[[[[[[[[    onSendRoutingInfoForSMResponse      ]]]]]]]]]]");
        System.out
                .println("\n>>>>>>>>>>>>>>>>> Received SendRoutingInfoForSMResponse from SS7 Server <<<<<<<<<<<<<<<<<");

        // Process the SendRoutingInfoForSMResponse here
        System.out.println("Received Parameters: \n\tIMSI: " + response.getIMSI().getData()
                + "\n\tLocation Info with LMSI: \n\t\t" + response.getLocationInfoWithLMSI().getNetworkNodeNumber());
    }

    @Override
    public void onReadyForSMResponse(ReadyForSMResponse response) {
        logger.info("Received ReadyForSMResponse (Client): " + response);
        // Handle ReadyForSMResponse logic here
    }

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest request) {
        logger.info("Received SendRoutingInfoForSMRequest (Client): " + request);
        // Handle SendRoutingInfoForSMRequest logic here
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
            // logger.debug(String.format("onDialogAccept for DialogId=%d
            // MAPExtensionContainer=%s",
            // mapDialog.getLocalDialogId(), extensionContainer));
            System.out
                    .println("\n[[[[[[[[[[    onDialogAccept      ]]]]]]]]]]");
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
            logger.debug(String.format("DialogClose for Dialog=%d", mapDialog.getLocalDialogId()));
        }

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogDelimiter
     * (org.mobicents.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogDelimiter(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogDelimiter for DialogId=%d", mapDialog.getLocalDialogId()));
        }
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
        if (logger.isDebugEnabled()) {
            logger.debug(String
                    .format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s MAPExtensionContainer=%s",
                            mapDialog.getLocalDialogId(), destReference, origReference, extensionContainer));
        }
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

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len - 1; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }

        // fuzzing
        // for (int i = 0; i < 1; i++){
        // data[randomGenerator.nextInt(len / 2)] = (byte)randomGenerator.nextInt(255);
        // }

        return data;
    }

    public static void main(String args[]) {
        logger.debug("*************************************");
        logger.debug("***       SctpClientLiveInput     ***");
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

        final SS7ClientLiveInput client = new SS7ClientLiveInput();

        logger.setLevel(org.apache.log4j.Level.DEBUG);

        try {
            client.initializeStack(ipChannelType);

            // wait for M3UA link
            boolean m3ua_connected = false;
            while (m3ua_connected == false) {
                for (As a : client.clientM3UAMgmt.getAppServers()) {
                    if (a.isConnected() && a.isUp()) {
                        m3ua_connected = true;
                    }
                }
            }

            client.initiateSendRoutingInfo();

            // Lets pause for 20 seconds so stacks are initialized properly
            // Thread.sleep(20000);

            // Mtp3TransferPrimitive mtp3TransferPrimitive =
            // client.clientM3UAMgmt.getMtp3TransferPrimitiveFactory().createMtp3TransferPrimitive(3,
            // 2, 0, 1, 2, 5,
            // hexStringToByteArray("0980030e190b12060011041111111111110b1207001204111111111111186516480433119839490402035ea26c08a106020102020138"));
            // client.clientM3UAMgmt.sendMessage(mtp3TransferPrimitive);

            // Open the file
            // FileInputStream fstream = new FileInputStream("input/short.json");
            // BufferedReader br = new BufferedReader(new InputStreamReader(fstream));

            // Connect to the named pipe
            RandomAccessFile br = new RandomAccessFile("input/pipe", "r");

            String strLine;

            // Read File Line By Line
            while (true) {
                while ((strLine = br.readLine()) != null) {
                    // Print the content on the console
                    // logger.debug(strLine);

                    String str = strLine;
                    int i = str.indexOf("sccp_raw");
                    while (i != -1) {
                        // logger.debug(strLine);
                        i += "sccp_raw\":".length();
                        str = str.substring(i).replaceAll(" ", "");

                        // can be also json arrray
                        String[] items;
                        if (str.startsWith("[")) {
                            int _marker_pos = str.indexOf("]");
                            if (_marker_pos > 0) {
                                str = str.substring(0, _marker_pos);
                            }
                            items = str.replaceAll("\\[", "").replaceAll("\\]", "").replaceAll("\\s", "").split(",");
                        } else {
                            items = new String[1];
                            items[0] = str;
                        }

                        // iterate over all raw items
                        for (String item : items) {
                            // logger.debug("str = " + str);
                            String s = item.split("\"")[1];
                            // logger.debug("s = " + s);

                            Mtp3TransferPrimitive mtp3TransferPrimitive = client.clientM3UAMgmt
                                    .getMtp3TransferPrimitiveFactory()
                                    .createMtp3TransferPrimitive(3, 2, 0, 1, 2, 5, hexStringToByteArray(s));
                            client.clientM3UAMgmt.sendMessage(mtp3TransferPrimitive);
                        }
                        i = str.indexOf("sccp_raw");
                    }

                    // TODO, remove if not needed
                    // added only for visibility, to not have many sctp streams in wireshark
                    Thread.sleep(100);
                }
                // logger.debug("Waiting ...");
                Thread.sleep(1000);
            }
            // Close the input stream
            // br.close();

            /*
             * Thread.sleep(1000);
             * GlobalTitle callingGT =
             * client.sccpProvider.getParameterFactory().createGlobalTitle("100000000000",
             * 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null,
             * NatureOfAddress.INTERNATIONAL);
             * GlobalTitle calledGT =
             * client.sccpProvider.getParameterFactory().createGlobalTitle("100000000000",
             * 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null,
             * NatureOfAddress.INTERNATIONAL);
             * SccpAddress callingParty =
             * client.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
             * RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, callingGT, 1, 8);
             * SccpAddress calledParty =
             * client.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
             * RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledGT, 2, 8);
             * SccpDataMessage sccpDataMessage;
             * sccpDataMessage =
             * client.sccpProvider.getMessageFactory().createDataMessageClass0(calledParty,
             * callingParty,
             * hexStringToByteArray("6516480433119839490402035ea26c08a106020102020138"), 0,
             * true, null, null);
             * client.sccpProvider.send(sccpDataMessage);
             * 
             * 
             * Thread.sleep(1000);
             * client.initiateUSSD();
             * 
             * Thread.sleep(1000);
             * callingGT =
             * client.sccpProvider.getParameterFactory().createGlobalTitle("111111111111",
             * 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null,
             * NatureOfAddress.INTERNATIONAL);
             * calledGT =
             * client.sccpProvider.getParameterFactory().createGlobalTitle("111111111111",
             * 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null,
             * NatureOfAddress.INTERNATIONAL);
             * 
             * 
             * callingParty =
             * client.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
             * RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, callingGT, 1, 8);
             * calledParty =
             * client.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
             * RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledGT, 2, 8);
             * ISDNAddressString origReference =
             * client.mapProvider.getMAPParameterFactory().createISDNAddressString(
             * AddressNature.international_number, NumberingPlan.land_mobile,
             * "11111111111");
             * ISDNAddressString destReference =
             * client.mapProvider.getMAPParameterFactory().createISDNAddressString(
             * AddressNature.international_number, NumberingPlan.land_mobile,
             * "111111111111111");
             * ISDNAddressString gsmSCFAddress =
             * client.mapProvider.getMAPParameterFactory().createISDNAddressString(
             * AddressNature.international_number, NumberingPlan.land_mobile,
             * "111111111111111");
             * 
             * 
             * MAPProvider mapProvider = client.mapStack.getMAPProvider();
             * 
             * MAPApplicationContextName acn =
             * MAPApplicationContextName.anyTimeEnquiryContext;
             * MAPApplicationContextVersion vers = MAPApplicationContextVersion.version3;
             * MAPApplicationContext mapAppContext = MAPApplicationContext.getInstance(acn,
             * vers);
             * 
             * SubscriberIdentity subscriberIdentity;
             * IMSI imsi =
             * mapProvider.getMAPParameterFactory().createIMSI("11111111111111");
             * subscriberIdentity =
             * mapProvider.getMAPParameterFactory().createSubscriberIdentity(imsi);
             * 
             * RequestedInfo requestedInfo =
             * mapProvider.getMAPParameterFactory().createRequestedInfo(
             * true,
             * true, null,
             * true,
             * DomainType.csDomain,
             * true,
             * true,
             * true);
             * 
             * 
             * try {
             * MAPDialogMobility curDialog =
             * mapProvider.getMAPServiceMobility().createNewDialog(mapAppContext,
             * callingParty, origReference, calledParty, destReference);
             * 
             * curDialog.addAnyTimeInterrogationRequest(subscriberIdentity, requestedInfo,
             * gsmSCFAddress, null);
             * curDialog.send();
             * 
             * } catch (MAPException ex) {
             * ex.printStackTrace();
             * }
             */

        } catch (Exception e) {
            e.printStackTrace();
        }
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
