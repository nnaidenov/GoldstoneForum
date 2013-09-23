<%@ Page Title="Categories" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="Categories.aspx.cs" Inherits="GoldstoneForum.Categories" %>

<asp:Content ID="ContentBody" ContentPlaceHolderID="MainContent" runat="server">
   
    <div id="gridBox">
        <h2>Categories</h2>
        <asp:GridView CssClass="table table-hover"
            PagerStyle-BorderStyle="None" BorderStyle="None" runat="server"
            ID="GridViewCategories"
            AllowPaging="True" PageSize="10"
            AllowSorting="True"
            ItemType="GoldstoneForum.Models.Category"
            AutoGenerateColumns="False"
            DataKeyNames="Id"
            SelectMethod="GridViewCategories_GetData">
            <Columns>
                <asp:TemplateField HeaderText="Category Name" SortExpression="Name">
                    <ItemTemplate>
                        <asp:HyperLink Text="<%#: Item.Name %>" runat="server"
                            NavigateUrl='<%# "Category.aspx?id=" + Item.Id %>' />
                    </ItemTemplate>
                </asp:TemplateField>
                <asp:TemplateField HeaderText="Questions">
                    <ItemTemplate>
                        <span><%# 
                              Item.Questions == null ? 0 : Item.Questions.Count %></span>
                    </ItemTemplate>
                </asp:TemplateField>
                <asp:TemplateField HeaderText="Last question">
                    <ItemTemplate>
                        <asp:HyperLink runat="server"
                            Visible="<%# HasLastQuestion(Item.Id) %>"
                            Text='<%#:GetLastQuestionTitle(Item.Id) %>'
                            NavigateUrl="<%# GetLastQuestionUrl(Item.Id) %>">
                        </asp:HyperLink>
                    </ItemTemplate>
                </asp:TemplateField>
            </Columns>
        </asp:GridView>

        <asp:Panel runat="server" ID="PanelAddCategory" Visible="false">
            <asp:TextBox ID="TextBoxNewCategory" runat="server" />
            <asp:Button CssClass="btn" ID="ButtonAddCategory" runat="server" Text="Add category"
                OnClick="ButtonAddCategory_Click"></asp:Button>
        </asp:Panel>
    </div>
</asp:Content>
