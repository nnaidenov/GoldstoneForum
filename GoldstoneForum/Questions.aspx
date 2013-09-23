<%@ Page Title="Questions" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="Questions.aspx.cs" Inherits="GoldstoneForum.Questions" %>

<asp:Content ID="ContentMain" ContentPlaceHolderID="MainContent" runat="server">
    <h2>Questions</h2>

    <div id="grid-questions-wrapper" class="well">
        <asp:UpdatePanel runat="server" UpdateMode="Conditional">
            <ContentTemplate>
                <asp:GridView ID="GridViewQuestions" runat="server"
                    AllowPaging="true" PageSize="10" AllowSorting="true"
                    DataKeyNames="Id" ItemType="GoldstoneForum.Models.Question"
                    SelectMethod="GridViewQuestions_GetData"
                    AutoGenerateColumns="false">
                    <Columns>
                        <asp:TemplateField HeaderText="Votes">
                            <ItemTemplate>
                                <asp:ImageButton ImageUrl="~/img/upvote.png" ImageAlign="Middle" Text="Vote"
                                    CssClass="votePositive" runat="server" OnCommand="Vote_Command"
                                    CommandName="Vote" CommandArgument="<%# Item.Id %>" Visible='<%# CanUserVoteOnQuestion(Item.Id) %>' />
                                <asp:ImageButton ImageUrl="~/img/downvote.png" ImageAlign="Middle" Text="Unvote"
                                    CssClass="voteNegative" runat="server" OnCommand="Vote_Command"
                                    CommandName="Unvote" CommandArgument="<%# Item.Id %>" Visible="<%# CanUserUnVoteOnQuestion(Item.Id) %>" />
                                <div runat="server" class="list-group-item"><span class="badge"><%# Item.Votes.Count%></span>votes</div>
                                <div runat="server" class="list-group-item"><span class="badge"><%# Item.Answers.Count %></span>answers</div>
                            </ItemTemplate>
                        </asp:TemplateField>
                        <asp:TemplateField HeaderText="Sort by Title" SortExpression="Title">
                            <ItemTemplate>
                                <div runat="server" class="col-md-8">
                                    <asp:HyperLink Font-Size="Large" runat="server" Text="<%#: Item.Title %>" CssClass="question-title"
                                        NavigateUrl='<%#"~/QuestionForm.aspx?id=" + Item.Id %>' />
                                </div>
                            </ItemTemplate>
                        </asp:TemplateField>
                        <asp:TemplateField HeaderText="Sort by Date" SortExpression="DatePosted">
                            <ItemTemplate>
                                <div runat="server" class="col-md-8">
                                    Asked on <span runat="server" class="question-date"><%# Item.DatePosted.ToString() %></span>
                                    in
                        <asp:HyperLink runat="server" CssClass="question-category"
                            NavigateUrl='<%#"Category.aspx?id=" + Item.Category.Id %>' Text="<%#: Item.Category.Name %>" />
                                    by <span runat="server" class="question-author">
                                        <%#: Item.User == null ? "anonymous": Item.User.UserName %> </span>
                                </div>
                            </ItemTemplate>
                        </asp:TemplateField>
                    </Columns>
                </asp:GridView>
            </ContentTemplate>
        </asp:UpdatePanel>
    </div>
</asp:Content>
