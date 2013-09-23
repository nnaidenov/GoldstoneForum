<%@ Page Title="Question" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="QuestionForm.aspx.cs" Inherits="GoldstoneForum.QuestionForm" %>

<%@ Register TagPrefix="asp" Namespace="AjaxControlToolkit" Assembly="AjaxControlToolkit" %>

<asp:Content ID="ContentMain" ContentPlaceHolderID="MainContent" runat="server">
    <asp:FormView ID="FormViewQuestion" runat="server" AllowPaging="false"
        ItemType="GoldstoneForum.Models.Question" SelectMethod="FormViewQuestion_GetItem">
        <ItemTemplate>
            <h2><%#: Item.Title %></h2>
            <div class="votingBox  well">
                <asp:ImageButton ImageUrl="~/img/upvote.png" ImageAlign="Middle" Text="Vote"
                    runat="server" OnCommand="VoteOnQuestion_Command"
                    CommandName="Vote" Visible='<%# CanUserVoteOnQuestion() %>' />
                <asp:ImageButton ImageUrl="~/img/downvote.png" ImageAlign="Middle" Text="Unvote"
                    runat="server" OnCommand="VoteOnQuestion_Command"
                    CommandName="Unvote" Visible="<%# CanUserUnVoteOnQuestion() %>" />

                <div runat="server" class="list-group-item"><span class="badge"><%# Item.Votes.Count%> votes</span></div>
                <div runat="server" class="list-group-item"><span class="badge"><%# Item.Answers.Count %> answers</span></div>
            </div>

            <div class="questionBoxQuestion">
                <div class="well"><%# Item.Text %></div>
                <div class="wellSmall">
                    Asked on <span runat="server" class="question-date"><%# Item.DatePosted.ToString() %></span>
                    in
                    <asp:HyperLink runat="server" CssClass="question-category"
                        NavigateUrl='<%#"Category.aspx?id=" + Item.Category.Id %>' Text="<%#: Item.Category.Name %>" />
                    by <span runat="server" class="question-author">
                        <%#: Item.User == null? "anonymous": Item.User.UserName %> </span>
                </div>
                <div class="controls">
                    <div class="btn-group">
                        <asp:Button ID="ButtonEditQuestion" runat="server" Text="Edit" CssClass="btn btn-default"
                            Visible="<%# CanUserEditOrRemoveQuestion() %>" OnCommand="ButtonEditQuestion_Command" />
                        <asp:Button ID="ButtonHideQuestion" runat="server" Text="Delete" CssClass="btn btn-default"
                            Visible="<%# CanUserEditOrRemoveQuestion() %>" OnCommand="ButtonHideQuestion_Command"
                            OnClientClick="return confirm('Do you want to delete the question?');" />
                    </div>
                </div>
            </div>
        </ItemTemplate>
    </asp:FormView>

    <hr />
    <hr />

    <asp:ListView ID="ListViewQuestionAnswers" runat="server" ItemType="GoldstoneForum.Models.Answer"
        SelectMethod="ListViewQuestionAnswers_GetData">
        <LayoutTemplate>
            <div id="itemPlaceholder" runat="server"></div>
            <ul class="pager">
                <asp:DataPager ID="DataPager" runat="server" PagedControlID="ListViewQuestionAnswers" PageSize="10">
                    <Fields>
                        <asp:NextPreviousPagerField ButtonCssClass="btn" ButtonType="Button" ShowPreviousPageButton="true" ShowNextPageButton="false" />
                        <asp:NumericPagerField CurrentPageLabelCssClass="btn disabled" NumericButtonCssClass="btn" ButtonType="Button" />
                        <asp:NextPreviousPagerField ShowPreviousPageButton="false" ButtonCssClass="btn" ButtonType="Button" ShowNextPageButton="true" />
                    </Fields>
                </asp:DataPager>
            </ul>
        </LayoutTemplate>
        <ItemTemplate>
            <div class="votingBox well">
                <asp:ImageButton ImageUrl="~/img/upvote.png" ImageAlign="Middle" Text="Vote"
                    runat="server" OnCommand="VoteOnAnswer_Command" CommandArgument="<%# Item.Id %>"
                    CommandName="Vote" Visible='<%# CanUserVoteOnAnswer(Item.Id) %>' />
                <asp:ImageButton ImageUrl="~/img/downvote.png" ImageAlign="Middle" Text="Unvote"
                    runat="server" OnCommand="VoteOnAnswer_Command" CommandArgument="<%# Item.Id %>"
                    CommandName="Unvote" Visible="<%# CanUserUnVoteOnAnswer(Item.Id) %>" />
                <div runat="server" class="list-group-item">
                    <span class="badge"><%# Item.Votes.Count%></span>
                    votes
                </div>
            </div>
            <div class="questionBoxFloatless">
                <div class="well">
                    <p><%# Item.Text %></p>
                </div>
                <div class="wellSmall" runat="server">
                    Answered on <span runat="server" class="answer-date"><%#Item.DatePosted.ToString() %></span>
                    by <span runat="server" class="answer-author">
                        <%#: Item.User == null? "anonymous" : Item.User.UserName %> </span>
                </div>
                <div class="controls">
                    <div class="btn-group">
                        <asp:Button ID="ButtonEditAnswer" runat="server" Text="Edit" CssClass="btn btn-default"
                            Visible="<%# CanUserEditOrRemoveAnswer(Item.Id) %>"
                            CommandArgument="<%# Item.Id %>" OnCommand="ButtonEditAnswer_Command" />
                        <asp:Button ID="ButtonHideAnswer" runat="server" Text="Delete" CssClass="btn btn-default"
                            Visible="<%# CanUserEditOrRemoveAnswer(Item.Id) %>"
                            OnClientClick="return confirm('Do you want to delete the answer?');"
                            CommandArgument="<%# Item.Id %>" OnCommand="ButtonHideAnswer_Command" />
                    </div>
                </div>
            </div>
        </ItemTemplate>
        <ItemSeparatorTemplate>
            <div style="clear: both"></div>
            <hr />
        </ItemSeparatorTemplate>
    </asp:ListView>

    <asp:Panel runat="server" ID="PanelEditorContainer">
        <div class="control-group">
            <asp:Label runat="server" AssociatedControlID="TextAnswer" CssClass="control-label">Answer</asp:Label>
            <asp:TextBox ID="TextAnswer" Height="250" TextMode="MultiLine" Width="500" runat="server" />

            <asp:HtmlEditorExtender
                TargetControlID="TextAnswer"
                runat="server" EnableSanitization="false" />
        </div>
        <div class="form-actions no-color">
            <asp:Button ID="PostAnswer" runat="server" OnClick="PostAnswer_Click" Text="Post answer" CssClass="btn"></asp:Button>
        </div>
    </asp:Panel>
</asp:Content>
