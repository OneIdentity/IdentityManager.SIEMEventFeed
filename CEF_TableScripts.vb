''' '''''''''''''''''''''''''''''''''''''''''''
''' Common Event Format (CEF) over syslog   '''
''' Solution Accelerator                    '''
''' Version: 1.0                            '''
''' Author: Serkan Cetin - One Identity     '''
''' Date: November 1, 2023                  '''
'''''''''''''''''''''''''''''''''''''''''''''''

''' DialogJournal - table scripts - Scripts(OnSaved)
''' Description: generate a CEF message for authentication attempts
Try
	If $MessageString:Text$.ToString.Contains("login") Then
		Dim CEFmessage As String = """" & $MessageString:Text$.ToString() & """"
		Dim CEFstring As String = CCC_CEFMessageBuilder("40",CEFmessage,$MessageDate:Date$.ToString(),$LogonUser$,"5")
		Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
	End If
Catch ex As Exception
	'placeholder for error handling.
End Try



''' Person - table scripts - Scripts(OnSaved)
''' Description: generate a CEF message when an identity is marked as high risk (IsSecurityIncident set to True or False)
Try
	If $IsSecurityIncident[C]:Bool$ AndAlso $IsSecurityIncident:Bool$ = True Then
		Dim CEFmessage As String = """A security risk has been raised for identity""" & _
		    " FirstName=""" & $FirstName$ & """" & _
		    " LastName=""" & $LastName$ & """"
		Dim CEFstring As String = CCC_CEFMessageBuilder("40",CEFmessage,$XDateUpdated:Date$.ToString(),$CentralAccount$,"5")
		Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
	ElseIf $IsSecurityIncident[C]:Bool$ AndAlso $IsSecurityIncident:Bool$ = False Then
		Dim CEFmessage As String = """A security risk has been removed for identity""" & _
		    " FirstName=""" & $FirstName$ & """" & _
		    " LastName=""" & $LastName$ & """"
		Dim CEFstring As String = CCC_CEFMessageBuilder("41",CEFmessage,$XDateUpdated:Date$.ToString(),$CentralAccount$)
		Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
	End If
Catch ex As Exception
	'placeholder for error handling.
End Try



''' PersonWantsOrg - table scripts - Scripts (OnSaved)
''' Description: generate a CEF message when an access request is submitted (New or OrderProduct), approved (Granted) or Assigned.
Try
	If $OrderState[C]:Bool$ = True AndAlso $OrderState$ = "OrderProduct" Then
		Dim CEFmessage As String = """User has submitted an access request""" & " Username=""" & $UID_PersonOrdered[D]$ & """" & _
		    " Resource=""" & $UID_ITShopOrgFinal[D]$ & """"
		Dim CEFstring As String = CCC_CEFMessageBuilder("10",CEFmessage,$XDateInserted:Date$.ToString(),$FK(UID_PersonOrdered).CentralAccount$)
		Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
	ElseIf $OrderState[C]:Bool$ = True AndAlso $OrderState$ = "Granted" Then
		Dim CEFmessage As String = """User access request has been approved""" & " Username=""" & $UID_PersonOrdered[D]$ & """" & _
		    " Resource=""" & $UID_ITShopOrgFinal[D]$ & """"
		Dim CEFstring As String = CCC_CEFMessageBuilder("11",CEFmessage,$XDateUpdated:Date$.ToString(),$FK(UID_PersonOrdered).CentralAccount$)
		Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
	ElseIf $OrderState[C]:Bool$ = True AndAlso $OrderState$ = "Assigned" Then
		Dim CEFmessage As String = """User access request has been granted""" & " Username=""" & $UID_PersonOrdered[D]$ & """" & _
		    " Resource=""" & $UID_ITShopOrgFinal[D]$ & """"
		Dim CEFstring As String = CCC_CEFMessageBuilder("12",CEFmessage,$XDateUpdated:Date$.ToString(),$FK(UID_PersonOrdered).CentralAccount$)
		Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
	ElseIf $OrderState[C]:Bool$ = True AndAlso $OrderState$ = "Dismissed" Then
		Dim CEFmessage As String = """User access request has been denied""" & " Username=""" & $UID_PersonOrdered[D]$ & """" & _
		    " Resource=""" & $UID_ITShopOrgFinal[D]$ & """"
		Dim CEFstring As String = CCC_CEFMessageBuilder("13",CEFmessage,$XDateUpdated:Date$.ToString(),$FK(UID_PersonOrdered).CentralAccount$)
		Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
	ElseIf $OrderState[C]:Bool$ = True AndAlso $Recommendation:Int$ = 1 AndAlso ($OrderState$ = "Granted" Or $OrderState$ = "Assigned") Then
		Dim CEFmessage As String = """User access request has been approved/granted, despite the system recommendation to deny.""" & " Username=""" & $UID_PersonOrdered[D]$ & """" & _
		    " Resource=""" & $UID_ITShopOrgFinal[D]$ & """"
		Dim CEFstring As String = CCC_CEFMessageBuilder("14",CEFmessage,$XDateUpdated:Date$.ToString(),$FK(UID_PersonOrdered).CentralAccount$,"5")
		Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
	End If
Catch ex As Exception
	'placeholder for error handling
End Try



''' AttestationCase - table scripts - Scripts (OnSaved)
''' Description: generate a CEF message when an access review case is approved and denied
Try
	If $IsClosed[C]:Bool$ = True AndAlso $IsGranted:Bool$ = True Then
		Dim CEFmessage As String = """Access review case has been approved""" & " Resource=""" & $DisplayName$ & """" & _
		    " ResourceUid=""" & $UID_AttestationCase[D]$ & """"
		Dim CEFstring As String = CCC_CEFMessageBuilder("20",CEFmessage,$XDateInserted:Date$.ToString())
		Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
	ElseIf $IsClosed[C]:Bool$ = True AndAlso $IsGranted:Bool$ = False Then
		Dim CEFmessage As String = """Access review case has been denied""" & " Resource=""" & $DisplayName$ & """" & _
		    " ResourceUid=""" & $UID_AttestationCase[D]$ & """"
		Dim CEFstring As String = CCC_CEFMessageBuilder("21",CEFmessage,$XDateInserted:Date$.ToString())
		Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
	ElseIf $IsClosed[C]:Bool$ = True AndAlso $Recommendation:Int$ = 1 AndAlso $IsGranted:Bool$ = True Then
		Dim CEFmessage As String = """Access review case has been approved, despite the recommendation to deny""" & " Resource=""" & $DisplayName$ & """" & _
		    " ResourceUid=""" & $UID_AttestationCase[D]$ & """"
		Dim CEFstring As String = CCC_CEFMessageBuilder("22",CEFmessage,$XDateInserted:Date$.ToString(),"","5")
		Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
	End If
Catch ex As Exception
	'placeholder for error handling
End Try



''' PersonInBaseTree - table scripts - script (OnSaved)
''' Description: generate a CEF message when a compliance violation is detected, and the exception approval is granted or denied
Try
	If $FK(UID_Org).UID_OrgRoot$ = "CPL-V-NonCompliance" Then
		If $IsDecisionMade:Bool$ = False Then
			Dim CEFmessage As String = """The user is in violation of compliance rule""" & _
			    " Username=""" & $UID_Person[D]$ & """" & _
			    " ComplianceRule=""" & $UID_Org[D]$ & """"
			Dim CEFstring As String = CCC_CEFMessageBuilder("30",CEFmessage,$XDateInserted:Date$.ToString(),$FK(UID_Person).CentralAccount$,"5")
			Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
		ElseIf $IsDecisionMade[C]:Bool$ AndAlso $IsExceptionGranted:Bool$ = True Then
			Dim CEFmessage As String = """The user has been granted exception approval for violation of the compliance rule""" & _
			    " Username=""" & $UID_Person[D]$ & """" & _
			    " ComplianceRule=""" & $UID_Org[D]$ & """"
			Dim CEFstring As String = CCC_CEFMessageBuilder("31",CEFmessage,$XDateUpdated:Date$.ToString(),$FK(UID_Person).CentralAccount$,"5")
			Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
		ElseIf $IsDecisionMade[C]:Bool$ AndAlso $IsExceptionGranted:Bool$ = False Then
			Dim CEFmessage As String = """The user has been denied exception approval for violation of the compliance rule""" & _
			    " Username=""" & $UID_Person[D]$ & """" & _
			    " ComplianceRule=""" & $UID_Org[D]$ & """"
			Dim CEFstring As String = CCC_CEFMessageBuilder("32",CEFmessage,$XDateUpdated:Date$.ToString(),$FK(UID_Person).CentralAccount$)
			Dim CefEntry As String = CCC_CEFMessageWriter(CEFstring)
		End If
	End If
Catch ex As Exception
	'placeholder for error handling
End Try
