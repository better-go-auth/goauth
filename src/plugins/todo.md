	// huma.Register(humaRouter, huma.Operation{
	// 	OperationID: "Au-8-SwitchCompany",
	// 	Method:      http.MethodPost,
	// 	Path:        path + "/switch-company",
	// 	Tags:        tags,
	// 	Middlewares: huma.Middlewares{providerS.Authorization("Au-8-SwitchCompany", nil, nil)},
	// }, handler.ChangeActiveCompany)






// func (aus Service[T]) ChangeActiveCompany(ctx context.Context, userId string, input ChangeActiveCompanyInput) (dtos.GResp[TokenResponse], error) {
// 	// 1. Verify membership
// 	var targetMember models.CompanyMember
// 	err := aus.Provider.GormConn.Where("user_id = ? AND company_id = ?", userId, input.CompanyID).First(&targetMember).Error
// 	if err != nil {
// 		return dtos.NotFoundErrS[TokenResponse]("User is not a member of this company"), err
// 	}
// 	if targetMember.Status == enums.MembershipBlocked {
// 		return dtos.BadReqM[TokenResponse]("User is blocked from this company"), errors.New("blocked from company")
// 	}

// 	// 2. Begin transaction to update current status
// 	tx := aus.Provider.GormConn.Begin()
// 	if tx.Error != nil {
// 		return dtos.InternalErrMS[TokenResponse](tx.Error.Error()), tx.Error
// 	}

// 	// Set all memberships for this user to is_current = false
// 	if err := tx.Model(&models.CompanyMember{}).Where(models.CompanyMemberFilter{UserID: userId}).Update("is_current", false).Error; err != nil {
// 		tx.Rollback()
// 		return dtos.InternalErrMS[TokenResponse]("Failed to reset active company"), err
// 	}

// 	// Set target membership to is_current = true
// 	if err := tx.Model(&models.CompanyMember{}).Where(models.CompanyMemberFilter{UserID: userId, CompanyID: input.CompanyID}).Update("is_current", true).Error; err != nil {
// 		tx.Rollback()
// 		return dtos.InternalErrMS[TokenResponse]("Failed to set active company"), err
// 	}

// 	// Fetch user details for response
// 	usr, err := generic.DbGetOneByID[models.User](tx, ctx, userId, nil)
// 	if err != nil {
// 		tx.Rollback()
// 		return dtos.NotFoundErrS[TokenResponse]("User not found"), err
// 	}

// 	// 3. Generate new session/token
// 	sessionID := ulid.Make().String()
// 	userRole := string(usr.Body.GetRole())
// 	if targetMember.RoleGroup != "" {
// 		userRole = string(targetMember.RoleGroup)
// 	}

// 	// Commit transaction before generating/saving session to avoid deadlock
// 	if err := tx.Commit().Error; err != nil {
// 		return dtos.InternalErrMS[TokenResponse](err.Error()), err
// 	}

// 	tokens, err := aus.UTIL_MakeSession(ctx, sessionID, userRole, userId, input.CompanyID, "", &SessionOpt{ClearSession: true})
// 	if err != nil {
// 		return dtos.InternalErrMS[TokenResponse](err.Error()), err
// 	}

// 	tasks.EnqueueAuditActivityLog(ctx, aus.Provider.QueueClient, aus.Provider.GormConn, tasks.AuditActivityLogPayload{
// 		CompanyID:   input.CompanyID,
// 		UserID:      userId,
// 		Action:      "CHANGE_ACTIVE_COMPANY",
// 		EntityType:  "user",
// 		EntityID:    userId,
// 		Summary:     "Switched active organization context",
// 		LogAudit:    true,
// 		LogActivity: true,
// 	})

// 	return dtos.SuccessS(TokenResponse{
// 		AuthTokens: *tokens,
// 		UserData:   usr.Body,
// 	}, 1), nil
// }
